"""Tests for CVE Intelligence module — routes.py + sync.py"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

# Vendor patch_url regex coverage (Batch 1) — NVD reference lists frozen as inline
# data so tests stay self-contained. Each list is the upstream `references` array
# from the CVE's NVD record at sync time; refresh manually if NVD adds entries.
_PATCH_URL_REFS: dict[str, list[str]] = {
    "CVE-2024-1086": [
        "http://www.openwall.com/lists/oss-security/2024/04/10/22",
        "http://www.openwall.com/lists/oss-security/2024/04/10/23",
        "http://www.openwall.com/lists/oss-security/2024/04/14/1",
        "http://www.openwall.com/lists/oss-security/2024/04/15/2",
        "http://www.openwall.com/lists/oss-security/2024/04/17/5",
        "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f342de4e2f33e0e39165d8639387aa6c19dff660",
        "https://github.com/Notselwyn/CVE-2024-1086",
        "https://kernel.dance/f342de4e2f33e0e39165d8639387aa6c19dff660",
        "https://lists.debian.org/debian-lts-announce/2024/06/msg00016.html",
        "https://lists.debian.org/debian-lts-announce/2024/06/msg00020.html",
    ],
    "CVE-2024-30040": [
        "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-30040",
        "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-30040",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-30040",
    ],
    "CVE-2024-23222": [
        "https://support.apple.com/en-us/120304",
        "https://support.apple.com/en-us/120309",
        "https://support.apple.com/en-us/120310",
        "https://support.apple.com/en-us/120311",
        "https://support.apple.com/en-us/126632",
        "http://seclists.org/fulldisclosure/2024/Feb/6",
        "http://seclists.org/fulldisclosure/2024/Jan/34",
        "http://seclists.org/fulldisclosure/2024/Jan/40",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/US43EQFC2IS66EA2CPAZFH2RQ6WD7PKF/",
        "https://support.apple.com/en-us/HT214055",
    ],
    "CVE-2024-44308": [
        "https://support.apple.com/en-us/121752",
        "https://support.apple.com/en-us/121753",
        "https://support.apple.com/en-us/121754",
        "https://support.apple.com/en-us/121755",
        "https://support.apple.com/en-us/121756",
        "http://seclists.org/fulldisclosure/2024/Nov/16",
        "https://lists.debian.org/debian-lts-announce/2024/12/msg00003.html",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-44308",
    ],
    "CVE-2024-21762": [
        "https://fortiguard.com/psirt/FG-IR-24-015",
        "https://fortiguard.com/psirt/FG-IR-24-015",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-21762",
    ],
    "CVE-2023-20198": [
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z",
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2023-20198",
    ],
}


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
        assert data["total_products"] == 1
        assert len(data["affected_products"]) == 1

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

    def test_lookup_next_calls_chain(self):
        """Single-CVE response embeds exploit_lookup + kev_detail (in_kev) + cwe_lookup pivots."""
        _seed_cve()
        r = client.get("/v1/cve/CVE-2024-1234")
        assert r.status_code == 200
        next_calls = r.json()["next_calls"]
        tools = [hint["tool"] for hint in next_calls]
        assert tools[0] == "exploit_lookup"
        assert "kev_detail" in tools
        assert "cwe_lookup" in tools
        cwe_hint = next(h for h in next_calls if h["tool"] == "cwe_lookup")
        assert cwe_hint["input"] == "CWE-120"
        kev_hint = next(h for h in next_calls if h["tool"] == "kev_detail")
        assert kev_hint["input"] == "CVE-2024-1234"

    def test_lookup_next_calls_omits_kev_when_not_in_kev(self):
        _seed_cve(cve_id="CVE-2024-7777", in_kev=0, kev_date_added=None)
        r = client.get("/v1/cve/CVE-2024-7777")
        next_calls = r.json()["next_calls"]
        assert all(h["tool"] != "kev_detail" for h in next_calls)

    def test_lookup_next_calls_omits_cwe_when_no_cwe_id(self):
        _seed_cve(cve_id="CVE-2024-7778", cwe_id=None, in_kev=0, kev_date_added=None)
        r = client.get("/v1/cve/CVE-2024-7778")
        next_calls = r.json()["next_calls"]
        # exploit_lookup + calculate_risk_score always emitted; kev_detail/cwe_lookup conditional
        assert [h["tool"] for h in next_calls] == ["exploit_lookup", "calculate_risk_score"]

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

    def test_cve_lookup_truncates_affected_products_to_20_by_default(self):
        products = [{"vendor": f"v{i}", "product": f"p{i}"} for i in range(50)]
        _seed_cve(cve_id="CVE-2024-9001", affected_products=products)
        r = client.get("/v1/cve/CVE-2024-9001")
        assert r.status_code == 200
        data = r.json()
        assert len(data["affected_products"]) == 20
        assert data["total_products"] == 50
        assert data["affected_products"][0]["product"] == "p0"
        assert data["affected_products"][19]["product"] == "p19"

    def test_cve_lookup_include_affected_products_returns_full_list(self):
        products = [{"vendor": f"v{i}", "product": f"p{i}"} for i in range(50)]
        _seed_cve(cve_id="CVE-2024-9002", affected_products=products)
        r = client.get("/v1/cve/CVE-2024-9002?include_affected_products=true")
        assert r.status_code == 200
        data = r.json()
        assert len(data["affected_products"]) == 50
        assert data["total_products"] == 50

    def test_cve_lookup_small_product_list_not_truncated(self):
        products = [{"vendor": f"v{i}", "product": f"p{i}"} for i in range(5)]
        _seed_cve(cve_id="CVE-2024-9003", affected_products=products)
        r = client.get("/v1/cve/CVE-2024-9003")
        assert r.status_code == 200
        data = r.json()
        assert len(data["affected_products"]) == 5
        assert data["total_products"] == 5

    def test_cve_lookup_exactly_20_products_not_truncated(self):
        products = [{"vendor": f"v{i}", "product": f"p{i}"} for i in range(20)]
        _seed_cve(cve_id="CVE-2024-9004", affected_products=products)
        r = client.get("/v1/cve/CVE-2024-9004")
        assert r.status_code == 200
        data = r.json()
        assert len(data["affected_products"]) == 20
        assert data["total_products"] == 20

    def test_cve_lookup_exactly_21_products_truncated_to_20(self):
        products = [{"vendor": f"v{i}", "product": f"p{i}"} for i in range(21)]
        _seed_cve(cve_id="CVE-2024-9005", affected_products=products)
        r = client.get("/v1/cve/CVE-2024-9005")
        assert r.status_code == 200
        data = r.json()
        assert len(data["affected_products"]) == 20
        assert data["total_products"] == 21
        assert data["affected_products"][19]["product"] == "p19"

    def test_cve_lookup_include_affected_products_query_param_forms(self):
        products = [{"vendor": f"v{i}", "product": f"p{i}"} for i in range(30)]
        _seed_cve(cve_id="CVE-2024-9006", affected_products=products)

        for truthy in ("true", "True", "TRUE", "1"):
            r = client.get(f"/v1/cve/CVE-2024-9006?include_affected_products={truthy}")
            assert r.status_code == 200, f"truthy form {truthy!r} failed"
            assert len(r.json()["affected_products"]) == 30, f"truthy form {truthy!r} did not enable full list"

        for falsy in ("false", "False", "FALSE", "0"):
            r = client.get(f"/v1/cve/CVE-2024-9006?include_affected_products={falsy}")
            assert r.status_code == 200, f"falsy form {falsy!r} failed"
            assert len(r.json()["affected_products"]) == 20, f"falsy form {falsy!r} returned full list unexpectedly"

        r = client.get("/v1/cve/CVE-2024-9006?include_affected_products=not-a-bool")
        assert r.status_code == 422

        r = client.get("/v1/cve/CVE-2024-9006")
        assert r.status_code == 200
        assert len(r.json()["affected_products"]) == 20

    def test_cve_lookup_truncates_references_to_10_by_default(self):
        refs = [f"https://example.com/advisory-{i}" for i in range(25)]
        _seed_cve(cve_id="CVE-2024-9201", refs=refs)
        r = client.get("/v1/cve/CVE-2024-9201")
        assert r.status_code == 200
        data = r.json()
        assert len(data["references"]) == 10
        assert data["total_references"] == 25
        assert data["references"][0] == "https://example.com/advisory-0"
        assert data["references"][9] == "https://example.com/advisory-9"

    def test_cve_lookup_include_full_references_returns_full_list(self):
        refs = [f"https://example.com/advisory-{i}" for i in range(25)]
        _seed_cve(cve_id="CVE-2024-9202", refs=refs)
        r = client.get("/v1/cve/CVE-2024-9202?include_full_references=true")
        assert r.status_code == 200
        data = r.json()
        assert len(data["references"]) == 25
        assert data["total_references"] == 25

    def test_cve_lookup_short_references_not_truncated(self):
        refs = [f"https://example.com/advisory-{i}" for i in range(3)]
        _seed_cve(cve_id="CVE-2024-9203", refs=refs)
        r = client.get("/v1/cve/CVE-2024-9203")
        assert r.status_code == 200
        data = r.json()
        assert len(data["references"]) == 3
        assert data["total_references"] == 3

    def test_cve_lookup_exactly_10_refs_not_truncated(self):
        refs = [f"https://example.com/advisory-{i}" for i in range(10)]
        _seed_cve(cve_id="CVE-2024-9204", refs=refs)
        r = client.get("/v1/cve/CVE-2024-9204")
        assert r.status_code == 200
        data = r.json()
        assert len(data["references"]) == 10
        assert data["total_references"] == 10

    def test_cve_lookup_patch_url_detected_beyond_default_cap(self):
        # patch URL at index 15 (well past the 10-ref cap) must still surface.
        refs = [f"https://example.com/noise-{i}" for i in range(15)]
        refs.append("https://github.com/advisories/GHSA-aaaa-bbbb-cccc")
        _seed_cve(cve_id="CVE-2024-9205", refs=refs)
        r = client.get("/v1/cve/CVE-2024-9205")
        assert r.status_code == 200
        data = r.json()
        assert len(data["references"]) == 10
        assert data["total_references"] == 16
        assert data["patch_available"] is True
        assert data["patch_url"] == "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"

    def test_cve_lookup_total_references_zero_when_no_refs(self):
        _seed_cve(cve_id="CVE-2024-9206", refs=[])
        r = client.get("/v1/cve/CVE-2024-9206")
        assert r.status_code == 200
        data = r.json()
        assert data["references"] == [] or "references" not in data
        assert data["total_references"] == 0

    @pytest.mark.parametrize(
        "cve_id,expected_substring",
        [
            ("CVE-2024-1086", "kernel"),
            ("CVE-2024-30040", "msrc.microsoft.com/update-guide/vulnerability/"),
            ("CVE-2024-23222", "support.apple.com/en-us/"),
            ("CVE-2024-44308", "support.apple.com/en-us/"),
            ("CVE-2024-21762", "fortiguard.com/psirt/FG-IR-"),
            ("CVE-2023-20198", "sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/"),
        ],
    )
    def test_cve_lookup_patch_url_vendor_detection(self, cve_id, expected_substring):
        # Batch 1: 6 vendor regex (MSRC modern, Apple HT+6digit, Fortinet PSIRT, kernel.org git, kernel.dance, Cisco).
        refs = _PATCH_URL_REFS[cve_id]
        assert refs, f"refs for {cve_id} is empty"
        _seed_cve(cve_id=cve_id, refs=refs)
        r = client.get(f"/v1/cve/{cve_id}?include_full_references=true")
        assert r.status_code == 200
        data = r.json()
        assert data["patch_available"] is True, f"{cve_id} patch_available should be True"
        assert expected_substring in data["patch_url"], (
            f"{cve_id} patch_url={data['patch_url']!r} missing {expected_substring!r}"
        )

    def test_cve_lookup_second_call_served_from_cache(self):
        # Cold call hits the SQL hydration path (get_cve + get_cve_sources +
        # get_related_cves_by_product) and writes the formatted dict to cache.
        # Hot call must short-circuit before any of those queries fire — assert
        # via patch.spy on get_cve.
        from unittest.mock import patch as _patch

        _seed_cve(cve_id="CVE-2024-7777")
        with _patch("cve.routes.aget_cve", new_callable=AsyncMock, wraps=__import__("db").aget_cve) as spy:
            r1 = client.get("/v1/cve/CVE-2024-7777")
            assert r1.status_code == 200
            r2 = client.get("/v1/cve/CVE-2024-7777")
            assert r2.status_code == 200
            assert r1.json() == r2.json()
            # First call hits get_cve once, second call must NOT.
            assert spy.call_count == 1

    def test_cve_lookup_cache_segregates_by_include_flags(self):
        # ?include_full_references=true must not serve a cached default-shape
        # response and vice versa. Two cold calls with different flags should
        # both invoke get_cve (no cross-shape pollution).
        from unittest.mock import patch as _patch

        _seed_cve(cve_id="CVE-2024-7778")
        with _patch("cve.routes.aget_cve", new_callable=AsyncMock, wraps=__import__("db").aget_cve) as spy:
            client.get("/v1/cve/CVE-2024-7778")
            client.get("/v1/cve/CVE-2024-7778?include_full_references=true")
            assert spy.call_count == 2


class TestCalculateRiskScore:
    def test_risk_score_kev_critical_path(self):
        _seed_cve(
            cve_id="CVE-2024-7100",
            cvss_v3=9.8,
            epss_score=0.92,
            in_kev=1,
            published="2024-09-01T00:00:00Z",
        )
        with patch("cve.routes.asearch_exploits_by_cve", new_callable=AsyncMock, return_value=([{"edb_id": 1}], False)):
            r = client.get("/v1/cve/CVE-2024-7100/risk_score")
        assert r.status_code == 200
        data = r.json()
        assert data["cve_id"] == "CVE-2024-7100"
        assert data["score"] >= 90.0
        assert data["label"] == "CRITICAL"
        assert data["has_public_poc"] is True
        assert data["components"]["in_kev"] is True
        assert "kev_with_public_poc" in data["boosters_applied"]
        assert "actively exploited" in data["urgency"].lower()

    def test_risk_score_low_signal(self):
        _seed_cve(
            cve_id="CVE-2024-7101",
            cvss_v3=2.5,
            epss_score=0.001,
            in_kev=0,
            published="2020-01-01T00:00:00Z",
        )
        with patch("cve.routes.asearch_exploits_by_cve", new_callable=AsyncMock, return_value=([], False)):
            r = client.get("/v1/cve/CVE-2024-7101/risk_score")
        assert r.status_code == 200
        data = r.json()
        assert data["label"] == "LOW"
        assert data["has_public_poc"] is False
        assert data["boosters_applied"] == []

    def test_risk_score_404_for_unknown_cve(self):
        r = client.get("/v1/cve/CVE-9999-0001/risk_score")
        assert r.status_code == 404
        msg = r.json()["error"]["message"]
        assert "CVE-9999-0001" in msg
        assert "not found" in msg.lower()

    def test_risk_score_invalid_cve_format_400(self):
        r = client.get("/v1/cve/not-a-cve/risk_score")
        assert r.status_code == 400


class TestGetCvssDetails:
    def test_critical_v31_vector(self):
        r = client.get("/v1/cvss/details", params={"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
        assert r.status_code == 200
        data = r.json()
        assert data["version"] == "3.1"
        assert data["base_score"] == 9.8
        assert data["base_severity"] == "CRITICAL"
        assert data["metrics"]["attack_vector"] == "NETWORK"
        assert data["metrics"]["scope"] == "UNCHANGED"

    def test_v30_vector_accepted(self):
        r = client.get("/v1/cvss/details", params={"vector": "CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:N/A:N"})
        assert r.status_code == 200
        assert r.json()["version"] == "3.0"

    def test_v2_vector_rejected_400(self):
        r = client.get("/v1/cvss/details", params={"vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C"})
        assert r.status_code == 400
        assert "Unrecognized" in r.json()["error"]["message"]

    def test_malformed_vector_400(self):
        r = client.get("/v1/cvss/details", params={"vector": "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
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
        assert "YYYY-MM-DD" in r.json()["error"]["message"]

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

    def test_search_cwe_id_filter(self):
        _seed_cve(cve_id="CVE-2024-8100", cwe_id="CWE-79")
        _seed_cve(cve_id="CVE-2024-8101", cwe_id="CWE-89")
        r = client.get("/v1/cves?cwe_id=CWE-79")
        assert r.status_code == 200
        cve_ids = [c["cve_id"] for c in r.json()["results"]]
        assert "CVE-2024-8100" in cve_ids
        assert "CVE-2024-8101" not in cve_ids

    def test_search_cwe_id_case_insensitive(self):
        _seed_cve(cve_id="CVE-2024-8110", cwe_id="cwe-120")
        r = client.get("/v1/cves?cwe_id=CWE-120")
        assert r.status_code == 200
        cve_ids = [c["cve_id"] for c in r.json()["results"]]
        assert "CVE-2024-8110" in cve_ids

    def test_search_cwe_id_invalid_format(self):
        r = client.get("/v1/cves?cwe_id=garbage")
        assert r.status_code == 400

    def test_search_cvss_min_filter(self):
        _seed_cve(cve_id="CVE-2024-8200", cvss_v3=4.0)
        _seed_cve(cve_id="CVE-2024-8201", cvss_v3=7.5)
        _seed_cve(cve_id="CVE-2024-8202", cvss_v3=9.8)
        r = client.get("/v1/cves?cvss_min=7.0")
        assert r.status_code == 200
        cve_ids = [c["cve_id"] for c in r.json()["results"]]
        assert "CVE-2024-8201" in cve_ids
        assert "CVE-2024-8202" in cve_ids
        assert "CVE-2024-8200" not in cve_ids

    def test_search_cvss_max_filter(self):
        _seed_cve(cve_id="CVE-2024-8210", cvss_v3=4.0)
        _seed_cve(cve_id="CVE-2024-8211", cvss_v3=7.5)
        r = client.get("/v1/cves?cvss_max=7.0")
        assert r.status_code == 200
        cve_ids = [c["cve_id"] for c in r.json()["results"]]
        assert "CVE-2024-8210" in cve_ids
        assert "CVE-2024-8211" not in cve_ids

    def test_search_cvss_range(self):
        _seed_cve(cve_id="CVE-2024-8220", cvss_v3=4.0)
        _seed_cve(cve_id="CVE-2024-8221", cvss_v3=7.5)
        _seed_cve(cve_id="CVE-2024-8222", cvss_v3=9.8)
        r = client.get("/v1/cves?cvss_min=5.0&cvss_max=8.0")
        assert r.status_code == 200
        cve_ids = [c["cve_id"] for c in r.json()["results"]]
        assert "CVE-2024-8221" in cve_ids
        assert "CVE-2024-8220" not in cve_ids
        assert "CVE-2024-8222" not in cve_ids

    def test_search_cvss_inverted_range_rejected(self):
        r = client.get("/v1/cves?cvss_min=8.0&cvss_max=5.0")
        assert r.status_code == 400

    def test_search_cvss_excludes_null(self):
        # CVEs with null cvss_v3 are excluded when a cvss_min/max filter is active (SQLite NULL semantics)
        _seed_cve(cve_id="CVE-2024-8230", cvss_v3=None, cvss_vector=None)
        r = client.get("/v1/cves?cvss_min=0.0")
        assert r.status_code == 200
        cve_ids = [c["cve_id"] for c in r.json()["results"]]
        assert "CVE-2024-8230" not in cve_ids

    def test_search_vendor_filter(self):
        _seed_cve(cve_id="CVE-2024-8300", affected_products=[{"vendor": "apache", "product": "struts"}])
        _seed_cve(cve_id="CVE-2024-8301", affected_products=[{"vendor": "nginx", "product": "nginx"}])
        r = client.get("/v1/cves?vendor=apache")
        assert r.status_code == 200
        cve_ids = [c["cve_id"] for c in r.json()["results"]]
        assert "CVE-2024-8300" in cve_ids
        assert "CVE-2024-8301" not in cve_ids

    def test_search_product_and_vendor_combined(self):
        # product matches row 1, vendor matches row 2 of same CVE — must NOT return that CVE
        from db import upsert_cve

        upsert_cve(
            {
                "cve_id": "CVE-2024-8310",
                "description": "test",
                "severity": "LOW",
                "cvss_v3": 3.0,
                "published": "2024-01-01T00:00:00Z",
                "affected_products": [
                    {"vendor": "vendor_a", "product": "product_x"},
                    {"vendor": "vendor_b", "product": "product_y"},
                ],
            }
        )
        # product=product_x matches row 1, vendor=vendor_b matches row 2 — no single row satisfies both
        r = client.get("/v1/cves?product=product_x&vendor=vendor_b")
        assert r.status_code == 200
        cve_ids = [c["cve_id"] for c in r.json()["results"]]
        assert "CVE-2024-8310" not in cve_ids

    def test_search_query_echo_populated(self):
        r = client.get("/v1/cves?severity=HIGH&cvss_min=7.0&limit=5")
        assert r.status_code == 200
        data = r.json()
        assert "query_echo" in data
        echo = data["query_echo"]
        assert echo["severity"] == "HIGH"
        assert echo["cvss_min"] == 7.0
        assert echo["limit"] == 5

    def test_search_query_echo_minimal(self):
        r = client.get("/v1/cves")
        assert r.status_code == 200
        data = r.json()
        assert "query_echo" in data
        echo = data["query_echo"]
        assert echo == {"limit": 50}

    def test_search_next_offset_populated_when_truncated(self):
        for i in range(5):
            _seed_cve(cve_id=f"CVE-2024-8400{i}", severity="LOW")
        r = client.get("/v1/cves?severity=LOW&limit=2&offset=0")
        assert r.status_code == 200
        data = r.json()
        assert data["truncated"] is True
        assert data["next_offset"] == data["offset"] + data["count"]

    def test_search_next_offset_omitted_on_last_page(self):
        for i in range(3):
            _seed_cve(cve_id=f"CVE-2024-8500{i}", severity="MEDIUM")
        r = client.get("/v1/cves?severity=MEDIUM&limit=10")
        assert r.status_code == 200
        data = r.json()
        assert data["truncated"] is False
        assert "next_offset" not in data

    def test_search_slim_default_drops_heavy_fields(self):
        _seed_cve(
            cve_id="CVE-2024-9101",
            severity="HIGH",
            description="A long description that should not appear in slim results.",
            refs=["https://example.com/advisory-1", "https://example.com/advisory-2"],
            affected_products=[{"vendor": "v", "product": f"p{i}"} for i in range(5)],
        )
        r = client.get("/v1/cves?severity=HIGH&limit=200")
        assert r.status_code == 200
        items = [c for c in r.json()["results"] if c["cve_id"] == "CVE-2024-9101"]
        assert len(items) == 1
        item = items[0]
        for dropped in (
            "description",
            "references",
            "affected_products",
            "cvss_breakdown",
            "first_seen_source",
            "first_seen_at",
        ):
            assert dropped not in item, f"{dropped} should be dropped from slim cve_search result"
        # honest count still surfaces so agents can decide to fetch full
        assert item["total_products"] == 5
        # core triage fields stay
        assert item["severity"] == "HIGH"
        assert "epss" in item and "kev" in item
        # verdict is response-level (post v1.25.x bloat fix), not per-row
        assert "verdict" in r.json()

    def test_search_item_includes_references_count(self):
        # B2 v1.30.0: agents need the ref count to decide whether cve_lookup chain
        # is worthwhile. Always int (default 0 when no refs), never null.
        _seed_cve(
            cve_id="CVE-2024-RC01",
            severity="HIGH",
            refs=["https://example.com/r-1", "https://example.com/r-2", "https://example.com/r-3"],
        )
        _seed_cve(cve_id="CVE-2024-RC02", severity="HIGH", refs=[])
        r = client.get("/v1/cves?severity=HIGH&limit=200")
        assert r.status_code == 200
        items = {c["cve_id"]: c for c in r.json()["results"]}
        assert "references_count" in items["CVE-2024-RC01"]
        assert items["CVE-2024-RC01"]["references_count"] == 3
        assert items["CVE-2024-RC02"]["references_count"] == 0
        assert isinstance(items["CVE-2024-RC02"]["references_count"], int)

    def test_search_item_includes_cwes_multi(self):
        # B2 v1.30.0: search items now mirror cve_lookup's multi-CWE list.
        # Legacy cwe_id preserved for backward-compat (cwes[0] == cwe_id).
        _seed_cve(
            cve_id="CVE-2024-CW01",
            severity="HIGH",
            cwe_id="CWE-79",
            cwes=["CWE-79", "CWE-352"],
        )
        r = client.get("/v1/cves?severity=HIGH&limit=200")
        assert r.status_code == 200
        item = next(c for c in r.json()["results"] if c["cve_id"] == "CVE-2024-CW01")
        assert item["cwe_id"] == "CWE-79"  # legacy single preserved
        assert item["cwes"] == ["CWE-79", "CWE-352"]  # multi additive

    def test_search_default_excludes_target_dependencies(self):
        # batch g v1.30.0: default cve_search ignores cve_products rows with
        # vulnerable=0 — those are CPE target_sw / target_hw entries (e.g. an OS
        # the *real* affected product runs on), not the actually-vulnerable component.
        # Existing rows with vulnerable=NULL are treated as vulnerable=1 (back-compat).
        from db import get_cve_db

        _seed_cve(
            cve_id="CVE-2024-VULN1",
            severity="CRITICAL",
            affected_products=[{"vendor": "linus", "product": "linux_kernel"}],
        )
        _seed_cve(
            cve_id="CVE-2024-VULN2",
            severity="HIGH",
            affected_products=[
                {"vendor": "google", "product": "chrome"},
                {"vendor": "linus", "product": "linux_kernel"},
            ],
        )
        # Mark the linux_kernel row in CVE-2024-VULN2 as a target dependency.
        with get_cve_db() as con:
            con.execute(
                "UPDATE cve_products SET vulnerable = 0 WHERE cve_id = ? AND product = ?",
                ("CVE-2024-VULN2", "linux_kernel"),
            )
            con.execute(
                "UPDATE cve_products SET vulnerable = 1 WHERE cve_id = ? AND product = ?",
                ("CVE-2024-VULN2", "chrome"),
            )
            con.execute(
                "UPDATE cve_products SET vulnerable = 1 WHERE cve_id = ? AND product = ?",
                ("CVE-2024-VULN1", "linux_kernel"),
            )
        r = client.get("/v1/cves?product=linux_kernel&limit=200")
        assert r.status_code == 200
        cve_ids = [c["cve_id"] for c in r.json()["results"]]
        assert "CVE-2024-VULN1" in cve_ids
        assert "CVE-2024-VULN2" not in cve_ids, (
            "linux_kernel as target_sw/target_hw must be excluded by default — use tagged=true to broaden"
        )

    def test_search_tagged_true_includes_target_dependencies(self):
        # batch g v1.30.0: opt-in tagged=true broadens the filter to include
        # CPE rows where the product is a target dependency rather than the
        # actually-vulnerable component.
        from db import get_cve_db

        _seed_cve(
            cve_id="CVE-2024-TAG1",
            severity="CRITICAL",
            affected_products=[{"vendor": "linus", "product": "linux_kernel"}],
        )
        _seed_cve(
            cve_id="CVE-2024-TAG2",
            severity="HIGH",
            affected_products=[
                {"vendor": "google", "product": "chrome"},
                {"vendor": "linus", "product": "linux_kernel"},
            ],
        )
        with get_cve_db() as con:
            con.execute(
                "UPDATE cve_products SET vulnerable = 0 WHERE cve_id = ? AND product = ?",
                ("CVE-2024-TAG2", "linux_kernel"),
            )
            con.execute(
                "UPDATE cve_products SET vulnerable = 1 WHERE cve_id = ? AND product = ?",
                ("CVE-2024-TAG2", "chrome"),
            )
            con.execute(
                "UPDATE cve_products SET vulnerable = 1 WHERE cve_id = ? AND product = ?",
                ("CVE-2024-TAG1", "linux_kernel"),
            )
        r_default = client.get("/v1/cves?product=linux_kernel&limit=200")
        r_tagged = client.get("/v1/cves?product=linux_kernel&tagged=true&limit=200")
        default_ids = {c["cve_id"] for c in r_default.json()["results"]}
        tagged_ids = {c["cve_id"] for c in r_tagged.json()["results"]}
        assert "CVE-2024-TAG2" not in default_ids
        assert "CVE-2024-TAG2" in tagged_ids
        assert "CVE-2024-TAG1" in tagged_ids
        assert tagged_ids >= default_ids, "tagged=true must be a superset of default"

    def test_search_null_vulnerable_treated_as_vulnerable(self):
        # batch g v1.30.0 back-compat: rows synced before the migration have
        # vulnerable=NULL — they must keep showing up in default search results
        # (otherwise upgrade would silently drop CVEs until full re-sync).
        from db import get_cve_db

        _seed_cve(
            cve_id="CVE-2024-NULL1",
            severity="HIGH",
            affected_products=[{"vendor": "v", "product": "legacy_app"}],
        )
        with get_cve_db() as con:
            con.execute(
                "UPDATE cve_products SET vulnerable = NULL WHERE cve_id = ?",
                ("CVE-2024-NULL1",),
            )
        r = client.get("/v1/cves?product=legacy_app&limit=200")
        assert r.status_code == 200
        cve_ids = [c["cve_id"] for c in r.json()["results"]]
        assert "CVE-2024-NULL1" in cve_ids

    def test_search_migration_adds_cpe_part_and_vulnerable_columns(self):
        # batch g v1.30.0 schema migration: ensure ALTER TABLE ran and the
        # composite index is in place.
        from db import get_cve_db

        with get_cve_db() as con:
            cols = {row[1] for row in con.execute("PRAGMA table_info(cve_products)")}
            assert "cpe_part" in cols
            assert "vulnerable" in cols
            indexes = {row[1] for row in con.execute("PRAGMA index_list(cve_products)")}
            assert "idx_products_vuln" in indexes

    def test_search_item_kev_in_kev_true_emits_full_shape(self):
        # B3 v1.30.0: when in_kev=True, search items now expand to include the full
        # CISA KEV record (vulnerability_name, vendor_project, etc.) — agents stop
        # paying a follow-up kev_detail call for triage.
        from db import upsert_kev_details

        _seed_cve(
            cve_id="CVE-2024-KEVT1",
            severity="CRITICAL",
            in_kev=1,
            kev_date_added="2024-03-15",
        )
        upsert_kev_details(
            "CVE-2024-KEVT1",
            due_date="2024-04-05",
            required_action="Apply vendor patch.",
            known_ransomware_use=True,
            vendor_project="ExampleVendor",
            product="ExampleProduct",
            vulnerability_name="ExampleShell",
            short_description="Auth bypass leading to RCE.",
            notes="https://example.com/advisory",
            cwes=["CWE-287"],
        )
        r = client.get("/v1/cves?severity=CRITICAL&kev=true&limit=200")
        assert r.status_code == 200
        item = next(c for c in r.json()["results"] if c["cve_id"] == "CVE-2024-KEVT1")
        kev = item["kev"]
        assert kev["in_kev"] is True
        assert kev["date_added"] == "2024-03-15"
        assert kev["vulnerability_name"] == "ExampleShell"
        assert kev["vendor_project"] == "ExampleVendor"
        assert kev["due_date"] == "2024-04-05"
        assert kev["known_ransomware_use"] is True
        assert kev["required_action"] == "Apply vendor patch."
        assert kev["cwes"] == ["CWE-287"]

    def test_search_item_kev_in_kev_false_drops_nulls(self):
        # B3 v1.30.0: when in_kev=False, the kev block collapses to a single field —
        # 11 null fields no longer pollute the response (~10KB / 50-result page).
        _seed_cve(cve_id="CVE-2024-KEVF1", severity="HIGH", in_kev=0, kev_date_added=None)
        r = client.get("/v1/cves?severity=HIGH&limit=200")
        assert r.status_code == 200
        item = next(c for c in r.json()["results"] if c["cve_id"] == "CVE-2024-KEVF1")
        assert item["kev"] == {"in_kev": False}, "in_kev=False rows must drop null fields"

    def test_search_item_cwes_omitted_when_empty(self):
        # When DB has no multi-CWE list, cwes is excluded (response_model_exclude_none=True).
        # Legacy cwe_id still emitted so backward-compat consumers keep working.
        _seed_cve(cve_id="CVE-2024-CW02", severity="HIGH", cwe_id="CWE-120", cwes=None)
        r = client.get("/v1/cves?severity=HIGH&limit=200")
        assert r.status_code == 200
        item = next(c for c in r.json()["results"] if c["cve_id"] == "CVE-2024-CW02")
        assert item["cwe_id"] == "CWE-120"
        assert "cwes" not in item

    def test_search_include_full_returns_full_payload(self):
        _seed_cve(
            cve_id="CVE-2024-9102",
            severity="CRITICAL",
            description="Visible only with include=full.",
            refs=["https://example.com/full-ref"],
            affected_products=[{"vendor": "v", "product": "p"}],
        )
        r = client.get("/v1/cves?severity=CRITICAL&include=full&limit=200")
        assert r.status_code == 200
        items = [c for c in r.json()["results"] if c["cve_id"] == "CVE-2024-9102"]
        assert len(items) == 1
        item = items[0]
        assert item["description"] == "Visible only with include=full."
        assert item["references"] == ["https://example.com/full-ref"]
        assert item["affected_products"] == [{"vendor": "v", "product": "p"}]

    def test_search_include_invalid_value_rejected(self):
        r = client.get("/v1/cves?include=verbose")
        assert r.status_code == 400
        assert "include must be 'full'" in r.json()["error"]["message"]

    def test_search_include_empty_treated_as_slim(self):
        _seed_cve(
            cve_id="CVE-2024-9103",
            severity="LOW",
            description="should be hidden with empty include",
        )
        r = client.get("/v1/cves?severity=LOW&include=&limit=200")
        assert r.status_code == 200
        items = [c for c in r.json()["results"] if c["cve_id"] == "CVE-2024-9103"]
        assert items, "expected seeded CVE in results"
        assert "description" not in items[0]

    def test_search_include_full_inherits_references_cap(self):
        # cve_search?include=full reuses _format_cve, so the 10-ref cap applies there too.
        # Documents the inherited behavior — full refs require cve_lookup?include_full_references=true.
        refs = [f"https://example.com/r-{i}" for i in range(25)]
        _seed_cve(cve_id="CVE-2024-9104", severity="HIGH", refs=refs)
        r = client.get("/v1/cves?severity=HIGH&include=full&limit=200")
        assert r.status_code == 200
        items = [c for c in r.json()["results"] if c["cve_id"] == "CVE-2024-9104"]
        assert items, "expected seeded CVE in results"
        item = items[0]
        assert len(item["references"]) == 10
        assert item["total_references"] == 25

    def test_search_global_hint_present_when_results_exist(self):
        _seed_cve(cve_id="CVE-2024-7700", severity="HIGH")
        r = client.get("/v1/cves?severity=HIGH&limit=5")
        assert r.status_code == 200
        data = r.json()
        assert data["count"] >= 1
        hint = data["hint"]
        assert hint is not None
        assert hint["tool"] == "cve_lookup"
        assert "drill" in hint["reason"].lower() or "cve_lookup" in hint["reason"].lower()
        assert "input" not in hint  # global hint, no specific cve_id

    def test_search_no_hint_on_empty_results(self):
        r = client.get("/v1/cves?product=nonexistentproduct999")
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 0
        assert data.get("hint") is None

    def test_cve_search_second_call_served_from_cache(self):
        # Cold call hits search_cves SQL; hot call must short-circuit before
        # the SQL fires. Spy on cve.routes.asearch_cves to assert call_count==1.
        # Also spy on save_cached_domain to confirm the cache was actually
        # written (silent CACHE_MAX_BYTES rejection would still pass call_count
        # but produce a perpetual cold path).
        from unittest.mock import patch as _patch

        _seed_cve(cve_id="CVE-2024-CACHE1", severity="HIGH")
        with (
            _patch("cve.routes.asearch_cves", new_callable=AsyncMock, wraps=__import__("db").asearch_cves) as spy,
            _patch(
                "cve.routes.asave_cached_domain", new_callable=AsyncMock, wraps=__import__("db").asave_cached_domain
            ) as save_spy,
        ):
            r1 = client.get("/v1/cves?severity=HIGH&limit=5")
            assert r1.status_code == 200
            r2 = client.get("/v1/cves?severity=HIGH&limit=5")
            assert r2.status_code == 200
            assert r1.json() == r2.json()
            assert spy.call_count == 1
            assert save_spy.call_count == 1, "cache write must fire on cold call"

    def test_cve_search_cache_segregates_by_query(self):
        # Distinct filters must produce distinct cache entries — a HIGH-severity
        # cached response must not be served for a CRITICAL-severity request.
        from unittest.mock import patch as _patch

        _seed_cve(cve_id="CVE-2024-CACHE2", severity="CRITICAL")
        with _patch("cve.routes.asearch_cves", new_callable=AsyncMock, wraps=__import__("db").asearch_cves) as spy:
            client.get("/v1/cves?severity=HIGH&limit=5")
            client.get("/v1/cves?severity=CRITICAL&limit=5")
            assert spy.call_count == 2

    def test_cve_search_cache_segregates_by_include_flag(self):
        # ?include=full returns extra fields (description/affected_products/...);
        # slim default must not be served for a full request.
        from unittest.mock import patch as _patch

        _seed_cve(cve_id="CVE-2024-CACHE3", severity="HIGH")
        with _patch("cve.routes.asearch_cves", new_callable=AsyncMock, wraps=__import__("db").asearch_cves) as spy:
            client.get("/v1/cves?severity=HIGH&limit=5")
            client.get("/v1/cves?severity=HIGH&limit=5&include=full")
            assert spy.call_count == 2


class TestExploitPivotHints:
    """Phase 6 cascade: exploit_lookup self-cascade."""

    def test_exploit_pivot_emits_cve_lookup_and_risk_score(self):
        from cve.routes import _exploit_pivot_hints

        hints = _exploit_pivot_hints("CVE-2024-3094")
        tools = [h.tool for h in hints]
        assert tools == ["cve_lookup", "calculate_risk_score"]
        assert all(h.input == "CVE-2024-3094" for h in hints)
        # cve_lookup hint documents chain to kev/cwe; risk_score hint documents triage value
        cve_hint = next(h for h in hints if h.tool == "cve_lookup")
        assert "kev_detail" in cve_hint.reason

    def test_exploit_pivot_no_blind_kev_or_cwe(self):
        """ExploitResponse has no in_kev / cwe_id schema — must NOT emit kev_detail/cwe_lookup
        directly (would risk 404 / missing-input wasted calls)."""
        from cve.routes import _exploit_pivot_hints

        hints = _exploit_pivot_hints("CVE-2024-3094")
        tools = [h.tool for h in hints]
        assert "kev_detail" not in tools
        assert "cwe_lookup" not in tools

    def test_exploit_pivot_rejects_invalid_cve_id(self):
        """Helper must validate input — refactor / test paths that bypass route guard
        should not produce hints steering agents to guaranteed 400/404 lookups."""
        from cve.routes import _exploit_pivot_hints

        assert _exploit_pivot_hints("") == []
        assert _exploit_pivot_hints("not-a-cve") == []
        assert _exploit_pivot_hints("CVE-bad") == []


class TestShodanEdbDedup:
    """exploit_lookup must not double-count when a Shodan ref URL points to an EDB-ID
    already present in the offline ExploitDB CSV mirror."""

    def test_shodan_edb_ids_extracts_from_description(self):
        from cve.routes import _shodan_edb_ids

        refs = {
            "results": [
                {"description": "https://www.exploit-db.com/exploits/50592"},
                {"description": "https://www.exploit-db.com/exploits/12345"},
                {"description": "https://example.com/other"},
            ]
        }
        assert _shodan_edb_ids(refs) == {"50592", "12345"}

    def test_shodan_edb_ids_handles_empty_and_malformed(self):
        from cve.routes import _shodan_edb_ids

        assert _shodan_edb_ids({}) == set()
        assert _shodan_edb_ids({"results": []}) == set()
        assert _shodan_edb_ids({"results": [None, {}, {"description": None}]}) == set()
        # Defense-in-depth: non-string description (int / list / dict) must not raise
        assert (
            _shodan_edb_ids({"results": [{"description": 123}, {"description": []}, {"description": {"url": "x"}}]})
            == set()
        )


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
            "total_products",
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
        # enrichment fields always present on single-CVE lookup
        expected_keys.add("patch_available")
        expected_keys.add("related_cves")
        # next_calls always present on single-CVE lookup (at minimum exploit_lookup)
        expected_keys.add("next_calls")
        # total_references always present on cve_lookup (default 0 when no refs)
        expected_keys.add("total_references")
        # patch_url only present when a patch URL exists (excluded by response_model_exclude_none=True)
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


class TestCveEnrichment:
    def test_patch_available_github_advisory(self):
        _seed_cve(
            cve_id="CVE-2024-9001",
            refs=["https://github.com/advisories/GHSA-abcd-1234-efgh"],
        )
        data = client.get("/v1/cve/CVE-2024-9001").json()
        assert data["patch_available"] is True
        assert data["patch_url"] == "https://github.com/advisories/GHSA-abcd-1234-efgh"

    def test_patch_available_github_commit(self):
        _seed_cve(
            cve_id="CVE-2024-9002",
            refs=["https://github.com/foo/bar/commit/a1b2c3d4e5f6789"],
        )
        data = client.get("/v1/cve/CVE-2024-9002").json()
        assert data["patch_available"] is True
        assert "a1b2c3d4e5f6789" in data["patch_url"]

    def test_patch_available_false(self):
        _seed_cve(
            cve_id="CVE-2024-9003",
            refs=["https://nvd.nist.gov/vuln/detail/CVE-2024-9003"],
        )
        data = client.get("/v1/cve/CVE-2024-9003").json()
        assert data["patch_available"] is False
        assert "patch_url" not in data

    def test_patch_available_empty_refs(self):
        _seed_cve(cve_id="CVE-2024-9004", refs=[])
        data = client.get("/v1/cve/CVE-2024-9004").json()
        assert data["patch_available"] is False
        assert "patch_url" not in data

    def test_patch_available_log4shell_description_signal(self):
        """Log4Shell-class CVE: no canonical patch URL in refs but description states fix shipped."""
        _seed_cve(
            cve_id="CVE-2024-9010",
            description=(
                "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration. "
                "From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality "
                "has been completely removed."
            ),
            refs=["http://packetstormsecurity.com/files/165225/Apache-Log4j2.html"],
        )
        data = client.get("/v1/cve/CVE-2024-9010").json()
        assert data["patch_available"] is True
        # Description-only signal: patch_url omitted by response_model_exclude_none (no canonical URL)
        assert data.get("patch_url") is None

    def test_patch_available_fixed_in_version_signal(self):
        """Description says 'fixed in version X.Y.Z' → patch_available=True."""
        _seed_cve(
            cve_id="CVE-2024-9011",
            description="Buffer overflow in component foo. This issue is fixed in version 9.2.3 of the library.",
            refs=["https://example.com/blog/post"],
        )
        data = client.get("/v1/cve/CVE-2024-9011").json()
        assert data["patch_available"] is True

    def test_patch_available_upgrade_to_signal(self):
        """Description says 'upgrade to version X.Y' → patch_available=True."""
        _seed_cve(
            cve_id="CVE-2024-9012",
            description="Authentication bypass in xyz product. Users should upgrade to version 5.10 immediately.",
            refs=["https://example.com/advisory"],
        )
        data = client.get("/v1/cve/CVE-2024-9012").json()
        assert data["patch_available"] is True

    def test_patch_available_no_fix_signal_in_description(self):
        """Description without remediation language stays patch_available=False."""
        _seed_cve(
            cve_id="CVE-2024-9013",
            description="Out-of-bounds read in foo when parsing untrusted input. No further details provided.",
            refs=["https://nvd.nist.gov/vuln/detail/CVE-2024-9013"],
        )
        data = client.get("/v1/cve/CVE-2024-9013").json()
        assert data["patch_available"] is False
        assert "patch_url" not in data

    def test_patch_available_url_takes_precedence_over_description(self):
        """When a canonical patch URL exists, both flag and URL surface; description fallback is moot."""
        _seed_cve(
            cve_id="CVE-2024-9014",
            description="Fixed in version 2.0.1 — see GHSA for details.",
            refs=["https://github.com/advisories/GHSA-zzzz-yyyy-xxxx"],
        )
        data = client.get("/v1/cve/CVE-2024-9014").json()
        assert data["patch_available"] is True
        assert data["patch_url"] == "https://github.com/advisories/GHSA-zzzz-yyyy-xxxx"

    def test_patch_available_oversized_description_skipped(self):
        """Pathologically long description (>10k chars) is skipped to keep regex O(n) bounded."""
        # "Fixed in version 9.9.9" buried inside a 12k-char wall of text. Detection should
        # short-circuit before scanning, so patch_available stays False.
        bloat = "x " * 6000  # 12000 chars
        _seed_cve(
            cve_id="CVE-2024-9015",
            description=f"{bloat} Fixed in version 9.9.9 of the library.",
            refs=["https://example.com/note"],
        )
        data = client.get("/v1/cve/CVE-2024-9015").json()
        assert data["patch_available"] is False

    def test_related_cves_populated(self):
        _seed_cve(
            cve_id="CVE-2024-9010",
            severity="HIGH",
            cvss_v3=8.0,
            affected_products=[{"vendor": "acme", "product": "uniquewidget"}],
        )
        _seed_cve(
            cve_id="CVE-2024-9011",
            severity="CRITICAL",
            cvss_v3=9.5,
            affected_products=[{"vendor": "acme", "product": "uniquewidget"}],
        )
        _seed_cve(
            cve_id="CVE-2024-9012",
            severity="MEDIUM",
            cvss_v3=5.0,
            affected_products=[{"vendor": "acme", "product": "uniquewidget"}],
        )
        data = client.get("/v1/cve/CVE-2024-9010").json()
        assert len(data["related_cves"]) == 2
        severities = [r["severity"] for r in data["related_cves"]]
        assert severities[0] == "CRITICAL"

    def test_related_cves_excludes_self(self):
        _seed_cve(cve_id="CVE-2024-9013", affected_products=[{"vendor": "acme", "product": "uniquewidget"}])
        data = client.get("/v1/cve/CVE-2024-9013").json()
        cve_ids = [r["cve_id"] for r in data["related_cves"]]
        assert "CVE-2024-9013" not in cve_ids

    def test_related_cves_empty_when_no_products(self):
        _seed_cve(cve_id="CVE-2024-9014", affected_products=[])
        data = client.get("/v1/cve/CVE-2024-9014").json()
        assert data["related_cves"] == []

    def test_related_cves_no_matches(self):
        _seed_cve(
            cve_id="CVE-2024-9015", affected_products=[{"vendor": "xyzzy", "product": "totally_unique_product_xyz123"}]
        )
        data = client.get("/v1/cve/CVE-2024-9015").json()
        assert data["related_cves"] == []

    def test_enrichment_absent_from_search(self):
        _seed_cve(cve_id="CVE-2024-9020", refs=["https://github.com/advisories/GHSA-abcd-1234-efgh"])
        data = client.get("/v1/cves?product=nginx&limit=5").json()
        for result in data.get("results", []):
            assert "patch_available" not in result
            assert "patch_url" not in result
            assert "related_cves" not in result


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
    @patch("cve.sync._nvd_request", new_callable=AsyncMock)
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

        count = asyncio.run(sync_nvd(full=False))
        assert count == 1

    @patch("cve.sync._nvd_request", new_callable=AsyncMock)
    def test_empty_response(self, mock_req):
        mock_req.return_value = {"totalResults": 0, "vulnerabilities": []}
        from cve.sync import sync_nvd

        count = asyncio.run(sync_nvd(full=False))
        assert count == 0


class TestSyncKev:
    @patch("cve.sync._client", new_callable=AsyncMock)
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

        count = asyncio.run(sync_kev())
        assert count == 1

        from db import get_cve

        cve = get_cve("CVE-2024-0001")
        assert cve is not None
        assert cve["in_kev"] == 1

    @patch("cve.sync._client", new_callable=AsyncMock)
    def test_kev_sync_writes_full_details(self, mock_client):
        """sync_kev() must populate kev_details with all CISA fields."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-44228",
                    "vendorProject": "Apache",
                    "product": "Log4j2",
                    "vulnerabilityName": "Log4Shell",
                    "dateAdded": "2021-12-10",
                    "shortDescription": "Apache Log4j2 JNDI features used in configuration...",
                    "requiredAction": "Apply updates per vendor instructions.",
                    "dueDate": "2021-12-24",
                    "knownRansomwareCampaignUse": "Known",
                    "notes": "https://logging.apache.org/log4j/2.x/security.html;",
                    "cwes": ["CWE-20", "CWE-400", "CWE-502"],
                }
            ]
        }
        mock_resp.raise_for_status.return_value = None
        mock_client.get.return_value = mock_resp

        from cve.sync import sync_kev
        from db import get_kev_details

        count = asyncio.run(sync_kev())
        assert count == 1

        details = get_kev_details("CVE-2021-44228")
        assert details is not None
        assert details["in_kev"] is True
        assert details["date_added"] == "2021-12-10"
        assert details["due_date"] == "2021-12-24"
        assert details["required_action"].startswith("Apply updates")
        assert details["known_ransomware_use"] is True
        assert details["vendor_project"] == "Apache"
        assert details["product"] == "Log4j2"
        assert details["vulnerability_name"] == "Log4Shell"
        assert details["short_description"].startswith("Apache Log4j2")
        assert details["notes"].startswith("https://logging.apache.org")
        assert details["cwes"] == ["CWE-20", "CWE-400", "CWE-502"]

    @patch("cve.sync._client", new_callable=AsyncMock)
    def test_kev_sync_ransomware_unknown_treated_false(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-9999",
                    "dateAdded": "2024-09-09",
                    "knownRansomwareCampaignUse": "Unknown",
                }
            ]
        }
        mock_resp.raise_for_status.return_value = None
        mock_client.get.return_value = mock_resp

        from cve.sync import sync_kev
        from db import get_cve, get_kev_details

        asyncio.run(sync_kev())
        # cves row + kev_details row must both be populated after sync
        assert get_cve("CVE-2024-9999") is not None
        details = get_kev_details("CVE-2024-9999")
        assert details is not None
        assert details["known_ransomware_use"] is False

    @patch("cve.sync._client", new_callable=AsyncMock)
    def test_kev_sync_creates_minimal_cve_when_absent(self, mock_client):
        """update_kev() returns False for unknown CVE -> upsert_cve() seeds minimal row,
        and kev_details upsert still runs."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2099-12345",
                    "shortDescription": "Hypothetical exploited vuln.",
                    "dateAdded": "2099-01-01",
                    "vendorProject": "Acme",
                    "product": "Widget",
                    "cwes": ["CWE-89"],
                }
            ]
        }
        mock_resp.raise_for_status.return_value = None
        mock_client.get.return_value = mock_resp

        from cve.sync import sync_kev
        from db import get_cve, get_kev_details

        asyncio.run(sync_kev())
        cve = get_cve("CVE-2099-12345")
        assert cve is not None
        assert cve["in_kev"] == 1
        details = get_kev_details("CVE-2099-12345")
        assert details is not None
        assert details["vendor_project"] == "Acme"
        assert details["product"] == "Widget"

    @patch("cve.sync._client", new_callable=AsyncMock)
    def test_kev_sync_cwes_match_canonical_pattern(self, mock_client):
        """Defensive: written CWE entries should match canonical CWE-<n> pattern."""
        import re

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-3030",
                    "dateAdded": "2024-03-01",
                    "cwes": ["CWE-79", "CWE-352"],
                }
            ]
        }
        mock_resp.raise_for_status.return_value = None
        mock_client.get.return_value = mock_resp

        from cve.sync import sync_kev
        from db import get_kev_details

        asyncio.run(sync_kev())
        details = get_kev_details("CVE-2024-3030")
        assert details is not None
        for cwe_id in details["cwes"]:
            assert re.fullmatch(r"CWE-\d+", cwe_id), f"unexpected cwe value: {cwe_id!r}"


class TestKevDetailEndpoint:
    def _seed_kev(self, cve_id: str = "CVE-2021-44228", **detail_overrides):
        """Helper: seed cves.in_kev=1 plus a kev_details row."""
        from db import upsert_kev_details

        _seed_cve(cve_id=cve_id, in_kev=1, kev_date_added="2021-12-10")
        details = {
            "due_date": "2021-12-24",
            "required_action": "Apply updates per vendor instructions.",
            "known_ransomware_use": True,
            "vendor_project": "Apache",
            "product": "Log4j2",
            "vulnerability_name": "Log4Shell",
            "short_description": "Apache Log4j2 JNDI features...",
            "notes": "https://logging.apache.org/log4j/2.x/security.html",
            "cwes": ["CWE-20", "CWE-400", "CWE-502"],
        }
        details.update(detail_overrides)
        upsert_kev_details(cve_id, **details)

    def test_kev_detail_200(self):
        self._seed_kev()
        r = client.get("/v1/kev/CVE-2021-44228")
        assert r.status_code == 200
        data = r.json()
        assert data["cve_id"] == "CVE-2021-44228"
        assert data["in_kev"] is True
        assert data["date_added"] == "2021-12-10"
        assert data["due_date"] == "2021-12-24"
        assert data["known_ransomware_use"] is True
        assert data["vendor_project"] == "Apache"
        assert data["product"] == "Log4j2"
        assert data["vulnerability_name"] == "Log4Shell"
        assert data["cwes"] == ["CWE-20", "CWE-400", "CWE-502"]

    def test_kev_detail_case_insensitive(self):
        self._seed_kev()
        r = client.get("/v1/kev/cve-2021-44228")
        assert r.status_code == 200
        assert r.json()["cve_id"] == "CVE-2021-44228"

    def test_kev_detail_404_non_kev(self):
        _seed_cve(cve_id="CVE-2024-7777", in_kev=0)
        r = client.get("/v1/kev/CVE-2024-7777")
        assert r.status_code == 404
        assert "KEV" in r.json()["error"]["message"]

    def test_kev_detail_404_unknown_cve(self):
        r = client.get("/v1/kev/CVE-2099-99999")
        assert r.status_code == 404

    def test_kev_detail_400_invalid_format(self):
        r = client.get("/v1/kev/not-a-cve")
        assert r.status_code in (400, 404, 422)

    def test_kev_detail_verdict_block(self):
        self._seed_kev()
        r = client.get("/v1/kev/CVE-2021-44228")
        verdict = r.json()["verdict"]
        assert verdict["deterministic"] is True
        assert "cisa_kev_cache" in verdict["sources_queried"]
        assert verdict["completeness"] == "complete"

    def test_kev_detail_next_calls_chain(self):
        """next_calls must surface cve_lookup + exploit_lookup + cwe_lookup per CWE."""
        self._seed_kev()
        r = client.get("/v1/kev/CVE-2021-44228")
        next_calls = r.json()["next_calls"]
        tools = [hint["tool"] for hint in next_calls]
        assert "cve_lookup" in tools
        assert "exploit_lookup" in tools
        # one cwe_lookup per CWE in the seed (3 entries)
        cwe_hints = [hint for hint in next_calls if hint["tool"] == "cwe_lookup"]
        assert len(cwe_hints) == 3
        assert {hint["input"] for hint in cwe_hints} == {"CWE-20", "CWE-400", "CWE-502"}
        # cve_lookup pivot first
        assert next_calls[0]["tool"] == "cve_lookup"
        assert next_calls[0]["input"] == "CVE-2021-44228"

    def test_kev_detail_no_cwes_omits_cwe_pivots(self):
        self._seed_kev(cwes=[])
        r = client.get("/v1/kev/CVE-2021-44228")
        next_calls = r.json()["next_calls"]
        assert all(hint["tool"] != "cwe_lookup" for hint in next_calls)

    def test_kev_detail_null_due_date_legacy(self):
        """Older KEV entries (pre-BOD 22-01) may not have a due_date."""
        self._seed_kev(due_date=None)
        r = client.get("/v1/kev/CVE-2021-44228")
        assert r.status_code == 200
        # exclude_none drops null fields
        assert "due_date" not in r.json()


class TestSyncCwe:
    """Tests for sync_cwe() — MITRE CWE catalog ZIP/CSV parser."""

    def _build_zip_with_csv(self, csv_text: str) -> bytes:
        import io
        import zipfile

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("1000.csv", csv_text)
        return buf.getvalue()

    def _csv_header(self) -> str:
        return (
            "CWE-ID,Name,Weakness Abstraction,Status,Description,Extended Description,"
            "Related Weaknesses,Weakness Ordinalities,Applicable Platforms,Background Details,"
            "Alternate Terms,Modes Of Introduction,Exploitation Factors,Likelihood of Exploit,"
            "Common Consequences,Detection Methods,Potential Mitigations,Observed Examples,"
            "Functional Areas,Affected Resources,Taxonomy Mappings,Related Attack Patterns,Notes\n"
        )

    def _csv_row(
        self,
        cwe_id: str,
        name: str,
        *,
        abstraction: str = "Base",
        status: str = "Stable",
        description: str = "Test description.",
        extended: str = "Extended.",
        related: str = "",
        likelihood: str = "Medium",
        mitigations: str = "",
        examples: str = "",
    ) -> str:
        cells = [
            cwe_id,
            name,
            abstraction,
            status,
            description,
            extended,
            related,
            "",
            "",
            "",
            "",
            "",
            "",
            likelihood,
            "",
            "",
            mitigations,
            examples,
            "",
            "",
            "",
            "",
            "",
        ]
        return ",".join(f'"{c}"' for c in cells) + "\n"

    def test_sync_cwe_writes_basic_record(self):
        from cve.sync import sync_cwe
        from db import get_cwe

        csv_text = self._csv_header() + self._csv_row(
            "79",
            "Improper Neutralization of Input During Web Page Generation",
            description="The product does not neutralize user-controllable input.",
            likelihood="High",
        )
        zip_bytes = self._build_zip_with_csv(csv_text)

        with patch("cve.sync._client.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = MagicMock(
                content=zip_bytes,
                raise_for_status=MagicMock(),
            )
            count = asyncio.run(sync_cwe())

        assert count == 1
        record = get_cwe("CWE-79")
        assert record is not None
        assert record["name"].startswith("Improper Neutralization")
        assert record["abstract_type"] == "Base"
        assert record["status"] == "Stable"
        assert record["likelihood"] == "High"

    def test_sync_cwe_parses_related_chain(self):
        from cve.sync import sync_cwe
        from db import get_cwe

        related = (
            "::NATURE:ChildOf:CWE ID:707:VIEW ID:1000:ORDINAL:Primary::"
            "::NATURE:ParentOf:CWE ID:80:VIEW ID:1000::"
            "::NATURE:ParentOf:CWE ID:81:VIEW ID:1000::"
        )
        csv_text = self._csv_header() + self._csv_row("79", "XSS", related=related)
        zip_bytes = self._build_zip_with_csv(csv_text)

        with patch("cve.sync._client.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = MagicMock(content=zip_bytes, raise_for_status=MagicMock())
            asyncio.run(sync_cwe())

        record = get_cwe("CWE-79")
        assert record["parent_cwe"] == "CWE-707"
        assert "CWE-80" in record["child_cwes"]
        assert "CWE-81" in record["child_cwes"]

    def test_sync_cwe_ignores_non_view_1000_relations(self):
        """Relations from view 699 (software dev) must not leak into research view 1000 results."""
        from cve.sync import sync_cwe
        from db import get_cwe

        related = "::NATURE:ChildOf:CWE ID:999:VIEW ID:699:ORDINAL:Primary::"
        csv_text = self._csv_header() + self._csv_row("79", "XSS", related=related)
        zip_bytes = self._build_zip_with_csv(csv_text)
        with patch("cve.sync._client.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = MagicMock(content=zip_bytes, raise_for_status=MagicMock())
            asyncio.run(sync_cwe())

        record = get_cwe("CWE-79")
        assert record["parent_cwe"] is None

    def test_sync_cwe_parses_mitigations_and_examples(self):
        from cve.sync import sync_cwe
        from db import get_cwe

        mitigations = (
            "::PHASE:Architecture and Design:DESCRIPTION:Use a vetted library.::"
            "::PHASE:Implementation:DESCRIPTION:Encode all user output.::"
        )
        examples = (
            "::REFERENCE:CVE-2018-1234:DESCRIPTION:Buffer overflow in foo.::"
            "::REFERENCE:CVE-2019-5678:DESCRIPTION:XSS in bar.::"
        )
        csv_text = self._csv_header() + self._csv_row("79", "XSS", mitigations=mitigations, examples=examples)
        zip_bytes = self._build_zip_with_csv(csv_text)
        with patch("cve.sync._client.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = MagicMock(content=zip_bytes, raise_for_status=MagicMock())
            asyncio.run(sync_cwe())

        record = get_cwe("CWE-79")
        assert len(record["mitigations"]) == 2
        assert any("vetted library" in m for m in record["mitigations"])
        assert any("Architecture and Design" in m for m in record["mitigations"])
        assert len(record["examples"]) == 2
        assert any("CVE-2018-1234" in e for e in record["examples"])

    def test_sync_cwe_skips_malformed_rows(self):
        """Empty CWE-ID or empty Name → row skipped, not raised."""
        from cve.sync import sync_cwe

        csv_text = self._csv_header() + ',"",Base,Stable,desc,ext,,,,,,,,Medium,,,,,,,,,\n'
        csv_text += self._csv_row("79", "Valid")
        zip_bytes = self._build_zip_with_csv(csv_text)
        with patch("cve.sync._client.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = MagicMock(content=zip_bytes, raise_for_status=MagicMock())
            count = asyncio.run(sync_cwe())
        assert count == 1

    def test_sync_cwe_oversize_zip_refused(self):
        from cve.sync import sync_cwe

        oversized = b"\x00" * (26 * 1024 * 1024)
        with patch("cve.sync._client.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = MagicMock(content=oversized, raise_for_status=MagicMock())
            count = asyncio.run(sync_cwe())
        assert count == 0


class TestCweLookupEndpoint:
    def _seed_cwe(self, cwe_id: str = "CWE-79", **overrides):
        from db import upsert_cwe

        defaults = {
            "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
            "description": "The product does not neutralize or incorrectly neutralizes user-controllable input.",
            "extended_description": "Cross-site scripting vulnerabilities occur when an attacker injects.",
            "abstract_type": "Base",
            "status": "Stable",
            "likelihood": "High",
            "mitigations": ["Architecture and Design — Use a vetted library."],
            "examples": ["CVE-2018-1234: XSS in widget."],
            "parent_cwe": "CWE-707",
            "child_cwes": ["CWE-80", "CWE-81"],
        }
        defaults.update(overrides)
        upsert_cwe(cwe_id, **defaults)

    def test_cwe_lookup_200(self):
        self._seed_cwe()
        r = client.get("/v1/cwe/CWE-79")
        assert r.status_code == 200
        data = r.json()
        assert data["cwe_id"] == "CWE-79"
        assert data["abstract_type"] == "Base"
        assert data["status"] == "Stable"
        assert data["likelihood"] == "High"
        assert data["parent_cwe"] == "CWE-707"
        assert data["child_cwes"] == ["CWE-80", "CWE-81"]

    def test_cwe_lookup_normalizes_lowercase(self):
        self._seed_cwe()
        r = client.get("/v1/cwe/cwe-79")
        assert r.status_code == 200
        assert r.json()["cwe_id"] == "CWE-79"

    def test_cwe_lookup_normalizes_bare_digits(self):
        self._seed_cwe()
        r = client.get("/v1/cwe/79")
        assert r.status_code == 200
        assert r.json()["cwe_id"] == "CWE-79"

    def test_cwe_lookup_404_unknown(self):
        r = client.get("/v1/cwe/CWE-999999")
        assert r.status_code == 404

    def test_cwe_lookup_400_invalid_format(self):
        r = client.get("/v1/cwe/not-a-cwe")
        assert r.status_code in (400, 404, 422)

    def test_cwe_lookup_cve_count_lower_bound(self):
        self._seed_cwe()
        _seed_cve(cve_id="CVE-2024-0001", cwe_id="CWE-79")
        _seed_cve(cve_id="CVE-2024-0002", cwe_id="CWE-79")
        _seed_cve(cve_id="CVE-2024-0003", cwe_id="CWE-89")
        r = client.get("/v1/cwe/CWE-79")
        assert r.json()["cve_count"] == 2

    def test_cwe_lookup_verdict_block(self):
        self._seed_cwe()
        r = client.get("/v1/cwe/CWE-79")
        verdict = r.json()["verdict"]
        assert verdict["deterministic"] is True
        assert "mitre_cwe_cache" in verdict["sources_queried"]

    def test_cwe_lookup_next_calls_chain(self):
        """next_calls must include cve_search (when CVEs exist), parent walk, and child drill-down."""
        self._seed_cwe()
        _seed_cve(cve_id="CVE-2024-0099", cwe_id="CWE-79")
        r = client.get("/v1/cwe/CWE-79")
        next_calls = r.json()["next_calls"]
        tools_inputs = [(hint["tool"], hint["input"]) for hint in next_calls]
        assert ("cve_search", "CWE-79") in tools_inputs
        assert ("cwe_lookup", "CWE-707") in tools_inputs
        assert ("cwe_lookup", "CWE-80") in tools_inputs
        assert ("cwe_lookup", "CWE-81") in tools_inputs

    def test_cwe_lookup_no_cves_omits_cve_search_pivot(self):
        self._seed_cwe(cwe_id="CWE-2222", parent_cwe=None, child_cwes=[])
        r = client.get("/v1/cwe/CWE-2222")
        next_calls = r.json().get("next_calls") or []
        assert all(hint["tool"] != "cve_search" for hint in next_calls)

    def test_cwe_lookup_no_parent_no_children_minimal_pivots(self):
        """A pillar-level CWE with no parent and no children but matched CVEs gets only cve_search hint."""
        self._seed_cwe(cwe_id="CWE-3333", parent_cwe=None, child_cwes=[])
        _seed_cve(cve_id="CVE-2024-XXXX", cwe_id="CWE-3333")
        r = client.get("/v1/cwe/CWE-3333")
        next_calls = r.json()["next_calls"]
        assert len(next_calls) == 1
        assert next_calls[0]["tool"] == "cve_search"

    def test_cwe_lookup_slim_default_drops_extended_and_caps_lists(self):
        """Default response: extended_description absent, mitigations + examples capped at 3 with honest totals."""
        many_mitigations = [f"Phase {i} — mitigation body {i}" for i in range(10)]
        many_examples = [f"CVE-2024-{i:04d}: example {i}" for i in range(8)]
        self._seed_cwe(cwe_id="CWE-1011", mitigations=many_mitigations, examples=many_examples)
        r = client.get("/v1/cwe/CWE-1011")
        assert r.status_code == 200
        data = r.json()
        assert "extended_description" not in data
        assert len(data["mitigations"]) == 3
        assert len(data["examples"]) == 3
        assert data["total_mitigations"] == 10
        assert data["total_examples"] == 8
        assert data["mitigations"][0] == "Phase 0 — mitigation body 0"

    def test_cwe_lookup_include_full_restores_everything(self):
        """include=full returns extended_description and full mitigations + examples lists."""
        many_mitigations = [f"Phase {i} — body {i}" for i in range(10)]
        many_examples = [f"CVE-2024-{i:04d}: ex {i}" for i in range(8)]
        self._seed_cwe(cwe_id="CWE-1012", mitigations=many_mitigations, examples=many_examples)
        r = client.get("/v1/cwe/CWE-1012?include=full")
        assert r.status_code == 200
        data = r.json()
        assert data["extended_description"] == "Cross-site scripting vulnerabilities occur when an attacker injects."
        assert len(data["mitigations"]) == 10
        assert len(data["examples"]) == 8
        assert data["total_mitigations"] == 10
        assert data["total_examples"] == 8

    def test_cwe_lookup_short_lists_not_truncated(self):
        """When lists are already smaller than the default cap, slim returns them in full."""
        self._seed_cwe(
            cwe_id="CWE-1013",
            mitigations=["only one"],
            examples=["CVE-2024-0001: only one"],
        )
        r = client.get("/v1/cwe/CWE-1013")
        data = r.json()
        assert len(data["mitigations"]) == 1
        assert len(data["examples"]) == 1
        assert data["total_mitigations"] == 1
        assert data["total_examples"] == 1

    def test_cwe_lookup_include_invalid_value_rejected(self):
        """include must be 'full' or omitted; arbitrary strings reject with 400."""
        r = client.get("/v1/cwe/CWE-79?include=verbose")
        assert r.status_code == 400
        assert "include" in r.json()["error"]["message"].lower()


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

    def test_upsert_cve_if_absent_fills_empty_cwe(self):
        from db import get_cve, upsert_cve, upsert_cve_if_absent

        upsert_cve({"cve_id": "CVE-2024-FILL1", "description": "x"})
        result = upsert_cve_if_absent({"cve_id": "CVE-2024-FILL1", "cwe_id": "CWE-79"})
        assert result is False
        assert get_cve("CVE-2024-FILL1")["cwe_id"] == "CWE-79"

    def test_upsert_cve_if_absent_preserves_existing_cwe(self):
        from db import get_cve, upsert_cve, upsert_cve_if_absent

        upsert_cve({"cve_id": "CVE-2024-FILL2", "cwe_id": "CWE-79"})
        upsert_cve_if_absent({"cve_id": "CVE-2024-FILL2", "cwe_id": "CWE-888"})
        assert get_cve("CVE-2024-FILL2")["cwe_id"] == "CWE-79"

    def test_upsert_cve_if_absent_fills_empty_affected_products(self):
        from db import get_cve, get_cve_db, upsert_cve, upsert_cve_if_absent

        upsert_cve({"cve_id": "CVE-2024-FILL3", "affected_products": []})
        upsert_cve_if_absent(
            {
                "cve_id": "CVE-2024-FILL3",
                "affected_products": [
                    {"vendor": "acme", "product": "foo"},
                    {"vendor": "acme", "product": "bar"},
                ],
            }
        )
        row = get_cve("CVE-2024-FILL3")
        assert row["affected_products"] != "[]"
        with get_cve_db() as con:
            count = con.execute("SELECT COUNT(*) FROM cve_products WHERE cve_id = ?", ("CVE-2024-FILL3",)).fetchone()[0]
        assert count == 2

    def test_upsert_cve_if_absent_preserves_strong_affected_products(self):
        from db import get_cve_db, upsert_cve, upsert_cve_if_absent

        upsert_cve({"cve_id": "CVE-2024-FILL4", "affected_products": [{"vendor": "nvd", "product": "strong"}]})
        upsert_cve_if_absent(
            {
                "cve_id": "CVE-2024-FILL4",
                "affected_products": [{"vendor": "mitre", "product": "weak"}],
            }
        )
        with get_cve_db() as con:
            rows = con.execute("SELECT product FROM cve_products WHERE cve_id = ?", ("CVE-2024-FILL4",)).fetchall()
        assert [r[0] for r in rows] == ["strong"]

    def test_upsert_cve_if_absent_ignores_empty_string_scalar(self):
        """Empty-string scalar from a source must not overwrite NULL (treated as unfilled)."""
        from db import get_cve, get_cve_db, upsert_cve_if_absent

        with get_cve_db() as con:
            con.execute(
                "INSERT INTO cves (cve_id, description, cwe_id) VALUES (?, NULL, NULL)",
                ("CVE-2024-FILL5",),
            )
        upsert_cve_if_absent({"cve_id": "CVE-2024-FILL5", "description": "", "cwe_id": ""})
        row = get_cve("CVE-2024-FILL5")
        assert row["description"] is None
        assert row["cwe_id"] is None

    def test_upsert_cve_if_absent_fills_whitespace_empty_json(self):
        """Legacy/malformed '[ ]' in affected_products must be treated as empty and backfilled."""
        from db import get_cve_db, upsert_cve_if_absent

        with get_cve_db() as con:
            con.execute(
                "INSERT INTO cves (cve_id, affected_products, refs) VALUES (?, ?, ?)",
                ("CVE-2024-FILL6", "[ ]", "[\n]"),
            )
        upsert_cve_if_absent(
            {
                "cve_id": "CVE-2024-FILL6",
                "affected_products": [{"vendor": "acme", "product": "foo"}],
                "refs": ["https://example.com"],
            }
        )
        with get_cve_db() as con:
            row = con.execute(
                "SELECT affected_products, refs FROM cves WHERE cve_id = ?", ("CVE-2024-FILL6",)
            ).fetchone()
            count = con.execute("SELECT COUNT(*) FROM cve_products WHERE cve_id = ?", ("CVE-2024-FILL6",)).fetchone()[0]
        assert "acme" in row[0]
        assert "example.com" in row[1]
        assert count == 1

    def test_search_uses_product_lower_index(self):
        """Regression guard: the LOWER(product) filter must hit a functional index,
        not a full table scan. Without an index, searches against the production
        cve_products table (~1M rows) degrade to O(n) per request. v1.30.0 adds
        idx_products_vuln on (LOWER(product), vulnerable) which can also serve this
        query — accept either functional index, reject scans/idx_products_cve_id."""
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
        assert "idx_products_product_lower" in plan_text or "idx_products_vuln" in plan_text, (
            f"Query plan should use a product functional index, got: {plan_text}"
        )


class TestSyncEpssValidation:
    @patch("cve.sync._client", new_callable=AsyncMock)
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

        asyncio.run(sync_epss())

        from db import get_cve

        cve = get_cve("CVE-2024-NAN1")
        assert cve["epss_score"] is None

    @patch("cve.sync._client", new_callable=AsyncMock)
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

        asyncio.run(sync_epss())

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

    @patch("cve.sync._nvd_request", new_callable=AsyncMock)
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

        asyncio.run(sync_nvd(full=False))
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

        # first_seen_source is only emitted under ?include=full (slim default drops it
        # for token efficiency on 50-item lists)
        r = client.get("/v1/cve/leading?include=full")
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

    def test_leading_slim_default_drops_description_and_references(self):
        """Default cve_leading list items omit description/cvss_breakdown/affected_products/
        references/first_seen_source/first_seen_at to avoid 50-item token bloat."""
        from db import record_cve_source, upsert_cve_if_absent

        upsert_cve_if_absent(
            {
                "cve_id": "CVE-2026-SLIM1",
                "description": "Long description that should be dropped from slim",
                "severity": "HIGH",
                "cvss_v3": 8.8,
                "refs": ["https://example.com/a", "https://example.com/b"],
                "affected_products": [{"product": "thing", "version_start": "1.0"}],
            }
        )
        record_cve_source("CVE-2026-SLIM1", "mitre")

        r = client.get("/v1/cve/leading")
        assert r.status_code == 200
        for cve in r.json()["results"]:
            if cve["cve_id"] == "CVE-2026-SLIM1":
                assert "description" not in cve
                assert "references" not in cve
                assert "affected_products" not in cve
                assert "cvss_breakdown" not in cve
                assert "first_seen_source" not in cve
                assert "first_seen_at" not in cve
                # slim still keeps these
                assert cve.get("severity") == "HIGH"
                assert "summary" in cve
                # verdict is response-level (post v1.25.x bloat fix), not per-item
                break
        else:
            raise AssertionError("CVE-2026-SLIM1 not in leading results")
        assert "verdict" in r.json(), "verdict must be at response root"

    def test_leading_include_full_restores_description_and_references(self):
        from db import record_cve_source, upsert_cve_if_absent

        upsert_cve_if_absent(
            {
                "cve_id": "CVE-2026-FULL1",
                "description": "Description that should be restored under include=full",
                "severity": "HIGH",
                "cvss_v3": 8.8,
                "refs": ["https://example.com/x"],
                "affected_products": [{"product": "thing"}],
            }
        )
        record_cve_source("CVE-2026-FULL1", "mitre")

        r = client.get("/v1/cve/leading?include=full")
        assert r.status_code == 200
        for cve in r.json()["results"]:
            if cve["cve_id"] == "CVE-2026-FULL1":
                assert cve.get("description", "").startswith("Description that should")
                assert cve.get("references") == ["https://example.com/x"]
                assert cve.get("affected_products") == [{"product": "thing"}]
                break
        else:
            raise AssertionError("CVE-2026-FULL1 not in leading results")

    def test_leading_invalid_include_value_rejected(self):
        r = client.get("/v1/cve/leading?include=bogus")
        assert r.status_code == 400
        assert "include must be" in r.json()["error"]["message"]

    def test_leading_global_hint_present_when_results_exist(self):
        from db import record_cve_source, upsert_cve_if_absent

        upsert_cve_if_absent({"cve_id": "CVE-2026-HINT1", "description": "hint test", "severity": "HIGH"})
        record_cve_source("CVE-2026-HINT1", "mitre")

        r = client.get("/v1/cve/leading?limit=10")
        assert r.status_code == 200
        data = r.json()
        if data["count"] >= 1:
            hint = data["hint"]
            assert hint is not None
            assert hint["tool"] == "cve_lookup"
            assert "input" not in hint  # global hint, not per-item

    def test_leading_no_hint_on_empty_results(self):
        # Direct unit assert on the helper — endpoint never naturally returns 0 in shared DB,
        # and offset>5000 is rejected. Helper must short-circuit on count<=0.
        from cve.routes import _cve_list_hint

        assert _cve_list_hint(0) is None
        assert _cve_list_hint(-1) is None
        assert _cve_list_hint(1) is not None


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

    def test_adp_backfills_when_cna_empty(self):
        from cve.sync import _parse_mitre_cve

        record = {
            "cveMetadata": {"cveId": "CVE-2024-90001", "state": "PUBLISHED"},
            "containers": {
                "cna": {},
                "adp": [
                    {
                        "descriptions": [{"lang": "en", "value": "ADP filled this"}],
                        "metrics": [
                            {"cvssV3_1": {"baseScore": 8.8, "vectorString": "CVSS:3.1/X", "baseSeverity": "HIGH"}}
                        ],
                        "problemTypes": [{"descriptions": [{"cweId": "CWE-89"}]}],
                        "references": [{"url": "https://adp.example/1"}],
                    }
                ],
            },
        }
        result = _parse_mitre_cve(record)
        assert result["description"] == "ADP filled this"
        assert result["cvss_v3"] == 8.8
        assert result["severity"] == "HIGH"
        assert result["cwe_id"] == "CWE-89"
        assert "https://adp.example/1" in result["refs"]
        assert {"source": "cisa-adp", "severity": "HIGH", "cvss_v3": 8.8, "cvss_v2": None} in result["severity_sources"]

    def test_cna_scalars_win_over_adp(self):
        from cve.sync import _parse_mitre_cve

        record = {
            "cveMetadata": {"cveId": "CVE-2024-90002", "state": "PUBLISHED"},
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "CNA desc"}],
                    "metrics": [{"cvssV3_1": {"baseScore": 7.5, "baseSeverity": "HIGH"}}],
                    "problemTypes": [{"descriptions": [{"cweId": "CWE-79"}]}],
                },
                "adp": [
                    {
                        "descriptions": [{"lang": "en", "value": "ADP desc"}],
                        "metrics": [{"cvssV3_1": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}}],
                        "problemTypes": [{"descriptions": [{"cweId": "CWE-89"}]}],
                    }
                ],
            },
        }
        result = _parse_mitre_cve(record)
        assert result["description"] == "CNA desc"
        assert result["cvss_v3"] == 7.5
        assert result["severity"] == "HIGH"
        assert result["cwe_id"] == "CWE-79"
        sources = {s["source"] for s in result["severity_sources"]}
        assert sources == {"mitre", "cisa-adp"}

    def test_adp_refs_merged_and_deduped(self):
        from cve.sync import _parse_mitre_cve

        record = {
            "cveMetadata": {"cveId": "CVE-2024-90003", "state": "PUBLISHED"},
            "containers": {
                "cna": {"references": [{"url": "https://x/a"}, {"url": "https://x/b"}]},
                "adp": [{"references": [{"url": "https://x/b"}, {"url": "https://x/c"}]}],
            },
        }
        result = _parse_mitre_cve(record)
        assert result["refs"] == ["https://x/a", "https://x/b", "https://x/c"]

    def test_adp_affected_products_merged(self):
        from cve.sync import _parse_mitre_cve

        record = {
            "cveMetadata": {"cveId": "CVE-2024-90004", "state": "PUBLISHED"},
            "containers": {
                "cna": {"affected": [{"vendor": "acme", "product": "cna-prod", "versions": [{"version": "1.0"}]}]},
                "adp": [{"affected": [{"vendor": "acme", "product": "adp-prod", "versions": [{"version": "2.0"}]}]}],
            },
        }
        result = _parse_mitre_cve(record)
        prods = {(p["vendor"], p["product"]) for p in result["affected_products"]}
        assert ("acme", "cna-prod") in prods
        assert ("acme", "adp-prod") in prods

    def test_adp_single_cisa_source_when_multiple_adp_entries(self):
        from cve.sync import _parse_mitre_cve

        record = {
            "cveMetadata": {"cveId": "CVE-2024-90005", "state": "PUBLISHED"},
            "containers": {
                "cna": {},
                "adp": [
                    {"metrics": [{"cvssV3_1": {"baseScore": 9.1, "baseSeverity": "CRITICAL"}}]},
                    {"metrics": [{"cvssV3_1": {"baseScore": 4.0, "baseSeverity": "MEDIUM"}}]},
                ],
            },
        }
        result = _parse_mitre_cve(record)
        cisa = [s for s in result["severity_sources"] if s["source"] == "cisa-adp"]
        assert len(cisa) == 1
        assert cisa[0]["cvss_v3"] == 9.1


class TestBatch1ReviewHardening:
    def test_adp_outer_cap_limits_entries(self):
        from cve.sync import _parse_mitre_cve

        record = {
            "cveMetadata": {"cveId": "CVE-2024-90006", "state": "PUBLISHED"},
            "containers": {
                "cna": {},
                "adp": [
                    {"affected": [{"vendor": "v", "product": f"p{i}", "versions": [{"version": "1.0"}]}]}
                    for i in range(11)
                ],
            },
        }
        result = _parse_mitre_cve(record)
        prods = {(p["vendor"], p["product"]) for p in result["affected_products"]}
        assert ("v", "p0") in prods
        assert ("v", "p10") not in prods

    def test_cna_description_length_capped(self):
        from cve.sync import _parse_mitre_cve

        record = {
            "cveMetadata": {"cveId": "CVE-2024-90007", "state": "PUBLISHED"},
            "containers": {"cna": {"descriptions": [{"lang": "en", "value": "A" * 5000}]}},
        }
        result = _parse_mitre_cve(record)
        assert len(result["description"]) == 4096

    def test_reference_url_length_capped(self):
        from cve.sync import _parse_mitre_cve

        long_url = "https://x/" + "a" * 3000
        record = {
            "cveMetadata": {"cveId": "CVE-2024-90008", "state": "PUBLISHED"},
            "containers": {"cna": {"references": [{"url": long_url}]}},
        }
        result = _parse_mitre_cve(record)
        assert len(result["refs"][0]) == 2048

    def test_severity_sources_rejects_unknown_source(self):
        from db import get_cve, upsert_cve_if_absent

        upsert_cve_if_absent(
            {
                "cve_id": "CVE-2024-ADPSS3",
                "description": "x",
                "severity_sources": [
                    {"source": "evilcorp", "severity": "LOW", "cvss_v3": 1.0, "cvss_v2": None},
                    {"source": "cisa-adp", "severity": "HIGH", "cvss_v3": 8.8, "cvss_v2": None},
                ],
            }
        )
        srcs = {s["source"] for s in get_cve("CVE-2024-ADPSS3")["severity_sources"]}
        assert "evilcorp" not in srcs
        assert "cisa-adp" in srcs

    def test_severity_sources_corrupt_existing_nonlist_safe(self):
        # GREEN-stays (defensive, not RED): must not crash, must not resurrect bad data.
        import json as _json

        from db import get_cve, get_cve_db, upsert_cve, upsert_cve_if_absent

        upsert_cve({"cve_id": "CVE-2024-ADPSS4", "description": "x"})
        with get_cve_db() as con:
            con.execute(
                "UPDATE cves SET severity_sources = ? WHERE cve_id = ?",
                (_json.dumps({"source": "nvd"}), "CVE-2024-ADPSS4"),
            )
        upsert_cve_if_absent(
            {
                "cve_id": "CVE-2024-ADPSS4",
                "severity_sources": [{"source": "cisa-adp", "severity": "HIGH", "cvss_v3": 8.8, "cvss_v2": None}],
            }
        )
        srcs = {s["source"] for s in get_cve("CVE-2024-ADPSS4")["severity_sources"]}
        assert srcs == {"cisa-adp"}


class TestAdpSeveritySourcesMerge:
    def test_upsert_cve_if_absent_persists_severity_sources_on_insert(self):
        from db import get_cve, upsert_cve_if_absent

        inserted = upsert_cve_if_absent(
            {
                "cve_id": "CVE-2024-ADPSS1",
                "description": "x",
                "severity_sources": [{"source": "cisa-adp", "severity": "HIGH", "cvss_v3": 8.8, "cvss_v2": None}],
            }
        )
        assert inserted is True
        ss = get_cve("CVE-2024-ADPSS1")["severity_sources"]
        assert {s["source"] for s in ss} == {"cisa-adp"}

    def test_upsert_cve_if_absent_merges_severity_sources_preserving_nvd(self):
        from db import get_cve, upsert_cve, upsert_cve_if_absent

        upsert_cve(
            {
                "cve_id": "CVE-2024-ADPSS2",
                "description": "nvd",
                "severity_sources": [{"source": "nvd", "severity": "LOW", "cvss_v3": 3.1, "cvss_v2": None}],
            }
        )
        inserted = upsert_cve_if_absent(
            {
                "cve_id": "CVE-2024-ADPSS2",
                "severity_sources": [
                    {"source": "mitre", "severity": "HIGH", "cvss_v3": 7.5, "cvss_v2": None},
                    {"source": "cisa-adp", "severity": "HIGH", "cvss_v3": 7.8, "cvss_v2": None},
                ],
            }
        )
        assert inserted is False
        ss = {s["source"]: s for s in get_cve("CVE-2024-ADPSS2")["severity_sources"]}
        assert set(ss) == {"nvd", "mitre", "cisa-adp"}
        assert ss["nvd"]["cvss_v3"] == 3.1


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
    @patch("cve.sync._client", new_callable=AsyncMock)
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

        count = asyncio.run(sync_mitre(full=False))
        assert count == 1
        row = get_cve("CVE-2024-70011")
        assert row is not None
        assert row["description"] == "Mitre-first bug"
        assert row["severity"] is None  # NVD will enrich later
        sources = get_cve_sources("CVE-2024-70011")
        assert len(sources) == 1
        assert sources[0]["source"] == "mitre"
        assert "CVERecord" in sources[0]["source_url"]

    @patch("cve.sync._client", new_callable=AsyncMock)
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

        count = asyncio.run(sync_mitre(full=False))
        assert count == 0
        assert get_cve("CVE-2024-70012") is None

    @patch("cve.sync._client", new_callable=AsyncMock)
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

        asyncio.run(sync_mitre(full=False))
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
            asyncio.run(sync_mitre(full=True))


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
    @patch("cve.sync._client", new_callable=AsyncMock)
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

        count = asyncio.run(sync_ghsa(full=False))
        assert count == 2
        assert get_cve("CVE-2024-80011") is not None
        assert get_cve("CVE-2024-80012") is not None
        sources = {s["source"] for s in get_cve_sources("CVE-2024-80011")}
        assert "ghsa" in sources

    @patch("cve.sync._client", new_callable=AsyncMock)
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

        count = asyncio.run(sync_ghsa(full=False))
        assert count == 1
        assert get_cve("CVE-2024-80013") is not None

    @patch("cve.sync._client", new_callable=AsyncMock)
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

        count = asyncio.run(sync_ghsa(full=False))
        assert count == 2
        assert get_cve("CVE-2024-80021") is not None
        assert get_cve("CVE-2024-80022") is not None
        assert mock_client.get.call_count == 2

    @patch("cve.sync._client", new_callable=AsyncMock)
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

        count = asyncio.run(sync_ghsa(full=False))
        # Boundary-equal advisory (updated_at == checkpoint) is now processed
        # (idempotent upsert); only the strictly-older one stops the walk (S253 fix).
        assert count == 1
        assert get_cve("CVE-2024-80031") is not None
        assert get_cve("CVE-2024-80032") is None

    @patch("cve.sync._client", new_callable=AsyncMock)
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

        asyncio.run(sync_ghsa(full=False))
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
            asyncio.run(sync_ghsa(full=True))


def _build_osv_resp(vuln: dict, status_code: int = 200):
    """Build a mock httpx response for _fetch_osv_vulnerability."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = vuln
    return resp


class TestSyncOsv:
    def test_osv_extracts_cve_from_aliases(self):
        from cve.sync import _parse_osv_vulnerability

        vuln = {"id": "GHSA-xxxx-yyyy-zzzz", "aliases": ["CVE-2026-91001"], "summary": "test bug"}
        result = _parse_osv_vulnerability(vuln)
        assert result["cve_id"] == "CVE-2026-91001"
        assert result.get("_skip") is not True

    def test_osv_skips_when_no_cve_alias(self):
        from cve.sync import _parse_osv_vulnerability

        vuln = {"id": "GHSA-xxxx-yyyy-zzzz", "aliases": ["PYSEC-2026-123"], "summary": "no CVE"}
        result = _parse_osv_vulnerability(vuln)
        assert result.get("_skip") is True

    def test_osv_parses_cvss_v3_vector(self):
        from cve.sync import _parse_osv_vulnerability

        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        vuln = {
            "id": "GHSA-test",
            "aliases": ["CVE-2026-91002"],
            "summary": "critical bug",
            "severity": [{"type": "CVSS_V3", "score": vector}],
        }
        result = _parse_osv_vulnerability(vuln)
        assert isinstance(result["cvss_v3"], float)
        assert result["cvss_v3"] == 9.8
        assert result["severity"] == "CRITICAL"

    def test_osv_parses_cwe_from_database_specific(self):
        from cve.sync import _parse_osv_vulnerability

        vuln = {
            "id": "GHSA-test",
            "aliases": ["CVE-2026-91003"],
            "summary": "xss bug",
            "database_specific": {"cwe_ids": ["CWE-79"]},
        }
        result = _parse_osv_vulnerability(vuln)
        assert result["cwe_id"] == "CWE-79"

    @patch("cve.sync._client", new_callable=AsyncMock)
    def test_osv_handles_404_gracefully(self, mock_client):
        from cve.sync import _fetch_osv_vulnerability

        mock_client.get.return_value = _build_osv_resp({}, status_code=404)
        result = asyncio.run(_fetch_osv_vulnerability("CVE-2026-91004"))
        assert result is None

    @patch("cve.sync._client", new_callable=AsyncMock)
    def test_osv_handles_network_error(self, mock_client):
        from cve.sync import _fetch_osv_vulnerability

        mock_client.get.side_effect = httpx.TimeoutException("timeout")
        result = asyncio.run(_fetch_osv_vulnerability("CVE-2026-91005"))
        assert result is None

    @patch("cve.sync._client", new_callable=AsyncMock)
    def test_osv_does_not_overwrite_nvd_data(self, mock_client):
        """NVD cvss_v3=9.8 must survive OSV enrichment with cvss_v3=5.0."""
        _seed_cve(
            cve_id="CVE-2026-91006",
            severity="CRITICAL",
            cvss_v3=9.8,
            cwe_id=None,
            published="2026-04-16T00:00:00Z",
        )

        osv_vuln = {
            "id": "GHSA-nvd-win",
            "aliases": ["CVE-2026-91006"],
            "summary": "OSV summary",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"}],
        }
        mock_client.get.return_value = _build_osv_resp(osv_vuln)

        from cve.sync import sync_osv
        from db import get_cve

        asyncio.run(sync_osv(full=False))
        row = get_cve("CVE-2026-91006")
        assert row["cvss_v3"] == 9.8
        assert row["severity"] == "CRITICAL"

    @patch("cve.sync._client", new_callable=AsyncMock)
    def test_osv_records_source_url(self, mock_client):
        _seed_cve(
            cve_id="CVE-2026-91007",
            severity=None,
            cvss_v3=None,
            cwe_id=None,
            published="2026-04-16T00:00:00Z",
        )

        osv_vuln = {
            "id": "GHSA-src-url",
            "aliases": ["CVE-2026-91007"],
            "summary": "source url test",
        }
        mock_client.get.return_value = _build_osv_resp(osv_vuln)

        from cve.sync import sync_osv
        from db import get_cve_sources

        asyncio.run(sync_osv(full=False))
        sources = get_cve_sources("CVE-2026-91007")
        osv_source = next((s for s in sources if s["source"] == "osv"), None)
        assert osv_source is not None
        assert osv_source["source_url"].startswith("https://osv.dev/vulnerability/")

    def test_osv_extracts_products_from_ecosystem(self):
        from cve.sync import _extract_products_from_osv_affected

        affected = [{"package": {"ecosystem": "PyPI", "name": "requests"}}]
        products = _extract_products_from_osv_affected(affected)
        assert len(products) == 1
        assert products[0]["vendor"] == "python"
        assert products[0]["product"] == "requests"

    def test_osv_full_sync_not_implemented(self):
        import pytest
        from cve.sync import sync_osv

        with pytest.raises(NotImplementedError):
            asyncio.run(sync_osv(full=True))

    def test_osv_backfill_selector_respects_since_and_limit(self):
        from db import get_cves_needing_osv_backfill, upsert_cve

        # Pre-cutoff CVE with NULL cvss_v3 — excluded by date
        upsert_cve(
            {
                "cve_id": "CVE-2026-91010",
                "description": "old",
                "cvss_v3": None,
                "cwe_id": None,
                "published": "2026-04-10T00:00:00Z",
            }
        )
        # Post-cutoff CVE with NULL cvss_v3 — should be selected
        upsert_cve(
            {
                "cve_id": "CVE-2026-91011",
                "description": "gap CVE",
                "cvss_v3": None,
                "cwe_id": None,
                "published": "2026-04-16T00:00:00Z",
            }
        )
        # Post-cutoff CVE with complete data — excluded (both non-NULL)
        upsert_cve(
            {
                "cve_id": "CVE-2026-91012",
                "description": "complete",
                "cvss_v3": 7.5,
                "cwe_id": "CWE-79",
                "published": "2026-04-16T00:00:00Z",
            }
        )

        result = get_cves_needing_osv_backfill(limit=10)
        assert "CVE-2026-91011" in result
        assert "CVE-2026-91010" not in result
        assert "CVE-2026-91012" not in result


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
    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
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

        with patch("cve.routes._exploit_client.get", new_callable=AsyncMock, side_effect=mock_get):
            r = client.get("/v1/exploit/CVE-2024-9999")
        assert r.status_code == 200
        data = r.json()
        assert data["cve_id"] == "CVE-2024-9999"
        assert data["has_public_exploit"] is True
        assert data["sources"]["github"]["found"] is True
        assert data["sources"]["github"]["count"] == 1
        assert data["sources"]["github"]["advisories"][0]["ghsa_id"] == "GHSA-xxxx-yyyy-zzzz"
        assert data["sources"]["shodan_refs"]["found"] is True
        assert data["sources"]["shodan_refs"]["count"] == 2
        # Cascade: cve_lookup + calculate_risk_score; kev/cwe deferred to cve_lookup's own next_calls
        next_calls = data["next_calls"]
        tools = [h["tool"] for h in next_calls]
        assert tools == ["cve_lookup", "calculate_risk_score"]
        assert all(h["input"] == "CVE-2024-9999" for h in next_calls)

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
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

        with patch("cve.routes._exploit_client.get", new_callable=AsyncMock, side_effect=mock_get):
            r = client.get("/v1/exploit/CVE-2024-0001")
        assert r.status_code == 200
        data = r.json()
        assert data["has_public_exploit"] is False
        assert data["exploits_found"] == 0
        assert "no public exploits" in data["summary"]

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    def test_exploit_shodan_refs_fails_gracefully(self, mock_cache_get, mock_cache_save):
        """Shodan CVEDB timeout should not prevent GitHub results from returning."""
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

        with patch("cve.routes._exploit_client.get", new_callable=AsyncMock, side_effect=mock_get):
            r = client.get("/v1/exploit/CVE-2024-5555")
        assert r.status_code == 200
        data = r.json()
        assert data["sources"]["github"]["found"] is True
        assert data["sources"]["shodan_refs"]["found"] is False
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
                "shodan_refs": {"found": False, "count": 0, "results": []},
            },
            "has_public_exploit": True,
            "summary": "CVE-2024-1111 — 1 public exploit(s) found",
        }
        with patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=cached_result):
            r = client.get("/v1/exploit/CVE-2024-1111")
        assert r.status_code == 200
        data = r.json()
        assert data["has_public_exploit"] is True


# =========== exploit_lookup Scope B tests ===========


class TestExploitLookupScopeB:
    """Verdict, structured exploits[], and backward-compat tests (Scope B)."""

    def _gh_ok(self, count=1):
        resp = MagicMock()
        resp.json.return_value = [
            {
                "ghsa_id": f"GHSA-{i:04d}",
                "summary": "Advisory",
                "severity": "high",
                "published_at": "2024-01-01T00:00:00Z",
                "references": [],
            }
            for i in range(count)
        ]
        resp.raise_for_status = MagicMock()
        return resp

    def _gh_err(self):
        resp = MagicMock()
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "error", request=MagicMock(), response=MagicMock(status_code=500)
        )
        return resp

    def _shodan_ok(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"references": ["https://poc.example.com"]}
        resp.raise_for_status = MagicMock()
        return resp

    def _shodan_404(self):
        resp = MagicMock()
        resp.status_code = 404
        resp.raise_for_status = MagicMock()
        return resp

    def _offline_row(self, edb_id=1, cve_id="CVE-2024-8888"):
        return {
            "edb_id": edb_id,
            "cve_id": cve_id,
            "date_published": "2024-03-01",
            "author": "tester",
            "type": "remote",
            "platform": "linux",
            "port": None,
            "verified": 1,
            "description": "PoC exploit",
            "source_url": f"https://www.exploit-db.com/exploits/{edb_id}",
            "date_added": "2024-03-01",
            "date_updated": "2024-03-01",
            "tags": "",
            "synced_at": "2024-04-01T00:00:00+00:00",
        }

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    @patch("cve.routes.asearch_exploits_by_cve", new_callable=AsyncMock)
    def test_exploit_offline_db_hit(self, mock_offline, mock_cache_get, mock_cache_save):
        """Offline DB hit returned when live sources empty."""
        mock_offline.return_value = ([self._offline_row()], False)

        def mock_get(url, **kwargs):
            if "github.com" in url:
                resp = MagicMock()
                resp.json.return_value = []
                resp.raise_for_status = MagicMock()
                return resp
            resp = MagicMock()
            resp.status_code = 404
            resp.raise_for_status = MagicMock()
            return resp

        with patch("cve.routes._exploit_client.get", new_callable=AsyncMock, side_effect=mock_get):
            r = client.get("/v1/exploit/CVE-2024-8888")
        assert r.status_code == 200
        data = r.json()
        assert data["has_public_exploit"] is True
        assert data["exploits_found"] == 1
        assert len(data["exploits"]) == 1
        assert data["exploits"][0]["edb_id"] == 1

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    @patch("cve.routes.asearch_exploits_by_cve", new_callable=AsyncMock)
    def test_exploit_mixed_sources_union(self, mock_offline, mock_cache_get, mock_cache_save):
        """exploits[] contains offline rows; count = offline + github."""
        mock_offline.return_value = ([self._offline_row(edb_id=10), self._offline_row(edb_id=11)], False)

        with patch(
            "cve.routes._exploit_client.get",
            new_callable=AsyncMock,
            side_effect=lambda url, **kw: self._gh_ok(2) if "github.com" in url else self._shodan_404(),
        ):
            r = client.get("/v1/exploit/CVE-2024-8888")
        data = r.json()
        assert data["exploits_found"] == 4  # 2 offline + 2 github
        assert len(data["exploits"]) == 2

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    @patch("cve.routes.asearch_exploits_by_cve", new_callable=AsyncMock)
    @patch("cve.routes._sync_age_seconds", new_callable=AsyncMock, return_value=3600)
    def test_exploit_verdict_complete_all_ok(self, mock_age, mock_offline, mock_cache_get, mock_cache_save):
        """completeness=complete when offline hit and no sources unavailable."""
        mock_offline.return_value = ([self._offline_row()], False)

        with patch(
            "cve.routes._exploit_client.get",
            new_callable=AsyncMock,
            side_effect=lambda url, **kw: self._gh_ok() if "github.com" in url else self._shodan_ok(),
        ):
            r = client.get("/v1/exploit/CVE-2024-8888")
        data = r.json()
        assert data["verdict"]["completeness"] == "complete"
        assert data["verdict"]["sources_unavailable"] == []

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    @patch("cve.routes.asearch_exploits_by_cve", new_callable=AsyncMock)
    @patch("cve.routes._sync_age_seconds", new_callable=AsyncMock, return_value=3600)
    def test_exploit_verdict_partial_github_down(self, mock_age, mock_offline, mock_cache_get, mock_cache_save):
        """github_advisory in sources_unavailable when GitHub errors."""
        mock_offline.return_value = ([], False)

        with patch(
            "cve.routes._exploit_client.get",
            new_callable=AsyncMock,
            side_effect=lambda url, **kw: self._gh_err() if "github.com" in url else self._shodan_404(),
        ):
            r = client.get("/v1/exploit/CVE-2024-8888")
        data = r.json()
        assert "github_advisory" in data["verdict"]["sources_unavailable"]

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    @patch("cve.routes.asearch_exploits_by_cve", new_callable=AsyncMock)
    @patch("cve.routes._sync_age_seconds", new_callable=AsyncMock, return_value=3600)
    def test_exploit_verdict_partial_shodan_down(self, mock_age, mock_offline, mock_cache_get, mock_cache_save):
        """shodan_cvedb in sources_unavailable when Shodan errors."""
        mock_offline.return_value = ([], False)

        def mock_get(url, **kwargs):
            if "github.com" in url:
                return self._gh_ok()
            raise httpx.ConnectTimeout("timeout")

        with patch("cve.routes._exploit_client.get", new_callable=AsyncMock, side_effect=mock_get):
            r = client.get("/v1/exploit/CVE-2024-8888")
        data = r.json()
        assert "shodan_cvedb" in data["verdict"]["sources_unavailable"]

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    @patch("cve.routes.asearch_exploits_by_cve", new_callable=AsyncMock)
    @patch("cve.routes._sync_age_seconds", new_callable=AsyncMock, return_value=3600)
    def test_exploit_verdict_minimal_all_down(self, mock_age, mock_offline, mock_cache_get, mock_cache_save):
        """completeness=minimal when all live sources down and no offline hit."""
        mock_offline.return_value = ([], False)

        def mock_get(url, **kwargs):
            raise httpx.ConnectTimeout("all down")

        with patch("cve.routes._exploit_client.get", new_callable=AsyncMock, side_effect=mock_get):
            r = client.get("/v1/exploit/CVE-2024-8888")
        data = r.json()
        assert data["verdict"]["completeness"] == "minimal"

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    @patch("cve.routes.asearch_exploits_by_cve", new_callable=AsyncMock)
    def test_exploit_verdict_data_age_max(self, mock_offline, mock_cache_get, mock_cache_save):
        """data_age_seconds = max(nvd_age, exploitdb_age)."""
        mock_offline.return_value = ([], False)
        nvd_age = 1000
        exploitdb_age = 5000

        def _mock_age(source):
            return nvd_age if source == "nvd" else exploitdb_age

        with (
            patch("cve.routes._sync_age_seconds", new_callable=AsyncMock, side_effect=_mock_age),
            patch(
                "cve.routes._exploit_client.get",
                new_callable=AsyncMock,
                side_effect=lambda url, **kw: self._gh_ok() if "github.com" in url else self._shodan_404(),
            ),
        ):
            r = client.get("/v1/exploit/CVE-2024-8888")
        data = r.json()
        assert data["verdict"]["data_age_seconds"] == 5000

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    @patch("cve.routes.asearch_exploits_by_cve", new_callable=AsyncMock)
    def test_exploit_verdict_stale_exploitdb_7d(self, mock_offline, mock_cache_get, mock_cache_save):
        """exploitdb_csv in sources_unavailable when last sync > 7 days ago."""
        mock_offline.return_value = ([], False)
        stale = 8 * 86400

        def _mock_age(source):
            return stale

        with (
            patch("cve.routes._sync_age_seconds", new_callable=AsyncMock, side_effect=_mock_age),
            patch(
                "cve.routes._exploit_client.get",
                new_callable=AsyncMock,
                side_effect=lambda url, **kw: self._gh_ok() if "github.com" in url else self._shodan_404(),
            ),
        ):
            r = client.get("/v1/exploit/CVE-2024-8888")
        data = r.json()
        assert "exploitdb_csv" in data["verdict"]["sources_unavailable"]

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    @patch("cve.routes.asearch_exploits_by_cve", new_callable=AsyncMock)
    @patch("cve.routes._sync_age_seconds", new_callable=AsyncMock, return_value=3600)
    def test_exploit_structured_shape(self, mock_age, mock_offline, mock_cache_get, mock_cache_save):
        """Response exploits[0] has edb_id, url, verified fields."""
        mock_offline.return_value = ([self._offline_row(edb_id=42)], False)

        with patch(
            "cve.routes._exploit_client.get",
            new_callable=AsyncMock,
            side_effect=lambda url, **kw: self._gh_ok() if "github.com" in url else self._shodan_404(),
        ):
            r = client.get("/v1/exploit/CVE-2024-8888")
        data = r.json()
        exploit = data["exploits"][0]
        assert exploit["edb_id"] == 42
        assert "exploit-db.com" in exploit["url"]
        assert exploit["verified"] is True

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    @patch("cve.routes.asearch_exploits_by_cve", new_callable=AsyncMock)
    @patch("cve.routes._sync_age_seconds", new_callable=AsyncMock, return_value=3600)
    def test_exploit_sources_shape(self, mock_age, mock_offline, mock_cache_get, mock_cache_save):
        """sources dict has github + shodan_refs keys with count field."""
        mock_offline.return_value = ([], False)

        with patch(
            "cve.routes._exploit_client.get",
            new_callable=AsyncMock,
            side_effect=lambda url, **kw: self._gh_ok() if "github.com" in url else self._shodan_404(),
        ):
            r = client.get("/v1/exploit/CVE-2024-8888")
        data = r.json()
        assert "github" in data["sources"]
        assert "shodan_refs" in data["sources"]
        assert "exploitdb" not in data["sources"]
        assert "count" in data["sources"]["github"]
        assert "count" in data["sources"]["shodan_refs"]


class TestExploitLookupVerdictHonesty:
    """Cache poisoning prevention: when an upstream source errors, the cached
    verdict must NOT report completeness=complete (it would otherwise serve a
    'no exploits found' answer for 1h TTL based on partial data)."""

    @patch("cve.routes.asearch_exploits_by_cve", new_callable=AsyncMock, return_value=([], False))
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes._search_shodan_refs", new_callable=AsyncMock)
    @patch("cve.routes._search_github_advisories", new_callable=AsyncMock)
    def test_github_error_downgrades_completeness(self, mock_gh, mock_shodan, mock_save, mock_cache, mock_offline):
        mock_gh.return_value = {"found": False, "count": 0, "advisories": [], "error": "upstream timeout"}
        mock_shodan.return_value = {"found": False, "count": 0, "results": []}
        r = client.get("/v1/exploit/CVE-2024-8888")
        assert r.status_code == 200
        verdict = r.json()["verdict"]
        assert verdict["completeness"] != "complete"
        assert "github_advisory" in verdict["sources_unavailable"]

    @patch("cve.routes.asearch_exploits_by_cve", new_callable=AsyncMock, return_value=([], False))
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes._search_shodan_refs", new_callable=AsyncMock)
    @patch("cve.routes._search_github_advisories", new_callable=AsyncMock)
    def test_shodan_error_downgrades_completeness(self, mock_gh, mock_shodan, mock_save, mock_cache, mock_offline):
        mock_gh.return_value = {"found": False, "count": 0, "advisories": []}
        mock_shodan.return_value = {"found": False, "count": 0, "results": [], "error": "upstream timeout"}
        r = client.get("/v1/exploit/CVE-2024-8888")
        assert r.status_code == 200
        verdict = r.json()["verdict"]
        assert verdict["completeness"] != "complete"
        assert "shodan_cvedb" in verdict["sources_unavailable"]


class TestExploitLookupParallelism:
    """GitHub Advisory + Shodan CVEDB fan-out must run in parallel, not serial."""

    @patch("cve.routes.asearch_exploits_by_cve", new_callable=AsyncMock, return_value=([], False))
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes._search_shodan_refs", new_callable=AsyncMock)
    @patch("cve.routes._search_github_advisories", new_callable=AsyncMock)
    def test_github_and_shodan_run_concurrently(self, mock_gh, mock_shodan, mock_save, mock_cache, mock_offline):
        import asyncio
        import time

        async def slow_gh(_cve):
            await asyncio.sleep(0.2)
            return {"found": False, "count": 0, "advisories": []}

        async def slow_shodan(_cve):
            await asyncio.sleep(0.2)
            return {"found": False, "count": 0, "results": []}

        mock_gh.side_effect = slow_gh
        mock_shodan.side_effect = slow_shodan

        start = time.monotonic()
        r = client.get("/v1/exploit/CVE-2024-8888")
        elapsed = time.monotonic() - start

        assert r.status_code == 200
        # Serial would be ~0.4s; parallel must complete in well under 0.35s.
        # Generous tolerance for thread-pool warmup + sqlite + response build.
        assert elapsed < 0.35, f"exploit_lookup ran serially: {elapsed:.3f}s"
        assert mock_gh.call_count == 1
        assert mock_shodan.call_count == 1


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
        assert set(r.json().keys()) == {
            "count",
            "total",
            "truncated",
            "offset",
            "summary",
            "results",
            "query_echo",
            "verdict",
            "hint",
        }
        assert "next_offset" not in r.json(), "next_offset must be omitted when truncated=False"

    def test_cve_search_response_includes_verdict(self):
        """Verdict is response-level (not per-row) — see v1.25.x verdict bloat fix."""
        _seed_cve(cve_id="CVE-2024-V001", severity="HIGH", cvss_v3=7.5)
        r = client.get("/v1/cves?severity=HIGH")
        assert r.status_code == 200
        data = r.json()
        assert len(data["results"]) > 0
        verdict = data.get("verdict")
        assert verdict is not None, "verdict must be at response root, not on each item"
        assert verdict["deterministic"] is True
        assert verdict["completeness"] == "complete"

    def test_cve_search_no_per_item_verdict(self):
        """Regression guard: per-item verdict was a bloat (~40% payload), kept top-level only."""
        _seed_cve(cve_id="CVE-2024-V001b", severity="HIGH")
        r = client.get("/v1/cves?severity=HIGH")
        for item in r.json()["results"]:
            assert "verdict" not in item, f"per-item verdict bloat regression: {item}"

    def test_cve_search_verdict_sources_queried(self):
        _seed_cve(cve_id="CVE-2024-V002", severity="HIGH")
        r = client.get("/v1/cves?severity=HIGH")
        v = r.json()["verdict"]
        assert "nvd_cache" in v["sources_queried"]

    def test_cve_search_verdict_falsifiable_fields(self):
        _seed_cve(cve_id="CVE-2024-V003", severity="HIGH")
        r = client.get("/v1/cves?severity=HIGH")
        v = r.json()["verdict"]
        expected = {"cve_id", "severity", "cvss_v3", "published", "references"}
        assert expected.issubset(set(v["falsifiable_fields"]))

    def test_cve_leading_response_includes_verdict(self):
        """Verdict is response-level (not per-row) — see v1.25.x verdict bloat fix."""
        r = client.get("/v1/cve/leading?limit=5")
        assert r.status_code == 200
        data = r.json()
        verdict = data.get("verdict")
        assert verdict is not None, "verdict must be at response root, not on each item"
        assert verdict["deterministic"] is True
        sources = set(verdict["sources_queried"])
        assert sources == {"mitre_cache", "ghsa_cache"}

    def test_cve_leading_no_per_item_verdict(self):
        """Regression guard against per-item verdict bloat returning."""
        r = client.get("/v1/cve/leading?limit=5")
        for item in r.json()["results"]:
            assert "verdict" not in item, f"per-item verdict bloat regression: {item}"


# =========== Crash recovery tests ===========


class TestSyncCrashRecovery:
    """Tests for NVD sync checkpoint/resume and in_progress status."""

    @patch("cve.sync._nvd_request", new_callable=AsyncMock)
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

        asyncio.run(sync_nvd(full=False))
        st = get_sync_status().get("nvd", {})
        assert st["status"] == "ok"

    @patch("time.sleep")
    @patch("cve.sync._nvd_request", new_callable=AsyncMock)
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

        count = asyncio.run(sync_nvd(full=True))
        assert count == 3
        st = get_sync_status().get("nvd", {})
        assert st["status"] == "ok"
        assert st.get("checkpoint") is None  # cleared on success

    @patch("cve.sync._nvd_request", new_callable=AsyncMock)
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

        count = asyncio.run(sync_nvd(full=True, resume=True))
        assert count == 3  # 2 from checkpoint + 1 new

        # Verify startIndex was 2
        call_args = mock_req.call_args
        assert call_args[0][0]["startIndex"] == 2

    @patch("cve.sync._nvd_request", new_callable=AsyncMock)
    def test_resume_no_checkpoint_starts_fresh(self, mock_req):
        """Resume with no checkpoint should start from 0."""
        from db import update_sync_status

        update_sync_status("nvd", 0, "ok", checkpoint=None)

        mock_req.return_value = {"totalResults": 0, "vulnerabilities": []}
        from cve.sync import sync_nvd

        asyncio.run(sync_nvd(full=True, resume=True))
        call_args = mock_req.call_args
        assert call_args[0][0]["startIndex"] == 0

    @patch("cve.sync.get_last_successful_sync")
    @patch("cve.sync._nvd_request", new_callable=AsyncMock)
    def test_delta_uses_last_sync_time(self, mock_req, mock_last):
        """Delta sync should use last successful sync time instead of hardcoded window."""
        mock_last.return_value = "2026-04-04T10:00:00+00:00"
        mock_req.return_value = {"totalResults": 0, "vulnerabilities": []}

        from cve.sync import sync_nvd

        asyncio.run(sync_nvd(full=False))

        call_args = mock_req.call_args[0][0]
        # Should be ~30min before last sync (09:30), not 2.5h before now
        assert "lastModStartDate" in call_args
        assert call_args["lastModStartDate"].startswith("2026-04-04T09:30")

    @patch("cve.sync._nvd_request", new_callable=AsyncMock)
    def test_delta_fallback_no_prior_sync(self, mock_req):
        """Delta sync without prior sync should fall back to 2.5h window."""
        from db import update_sync_status

        # Clear NVD sync status
        update_sync_status("nvd", 0, "error")

        mock_req.return_value = {"totalResults": 0, "vulnerabilities": []}
        from cve.sync import sync_nvd

        asyncio.run(sync_nvd(full=False))
        # Should not crash, just use fallback window
        assert mock_req.called

    @patch("time.sleep")
    @patch("cve.sync._nvd_request", new_callable=AsyncMock)
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

        count = asyncio.run(sync_nvd(full=True))
        assert count == 2

        st = get_sync_status().get("nvd", {})
        assert st["status"] == "error"
        # Checkpoint must be preserved for --resume
        assert st["checkpoint"] is not None
        cp = json.loads(st["checkpoint"])
        assert cp["start_index"] == 2
        assert cp["total_processed"] == 2

    @patch("cve.sync._nvd_request", new_callable=AsyncMock)
    def test_corrupt_checkpoint_starts_fresh(self, mock_req):
        """Corrupt checkpoint JSON should be ignored, sync starts from 0."""
        from db import update_sync_status

        # Set a non-dict JSON checkpoint
        update_sync_status("nvd", 0, "in_progress", checkpoint='"just_a_string"')

        mock_req.return_value = {"totalResults": 0, "vulnerabilities": []}
        from cve.sync import sync_nvd

        asyncio.run(sync_nvd(full=True, resume=True))
        call_args = mock_req.call_args[0][0]
        assert call_args["startIndex"] == 0

    @patch("cve.sync._nvd_request", new_callable=AsyncMock)
    def test_negative_checkpoint_starts_fresh(self, mock_req):
        """Checkpoint with negative values should be ignored."""
        import json

        from db import update_sync_status

        cp = json.dumps({"start_index": -5, "total_processed": -1})
        update_sync_status("nvd", 0, "in_progress", checkpoint=cp)

        mock_req.return_value = {"totalResults": 0, "vulnerabilities": []}
        from cve.sync import sync_nvd

        asyncio.run(sync_nvd(full=True, resume=True))
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

    @patch("cve.routes.aget_cve", new_callable=AsyncMock)
    def test_bulk_cve_success(self, mock_get):
        mock_get.return_value = dict(self._MOCK_CVE)
        r = client.post("/v1/cves/bulk", json={"cve_ids": ["CVE-2024-3094", "CVE-2021-44228"]})
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 2
        assert data["successful"] == 2
        assert data["failed"] == 0
        assert len(data["results"]) == 2

    @patch("cve.routes.aget_cve", new_callable=AsyncMock)
    def test_bulk_cve_items_carry_next_calls(self, mock_get):
        mock_get.return_value = dict(self._MOCK_CVE)
        r = client.post("/v1/cves/bulk", json={"cve_ids": ["CVE-2024-3094"]})
        assert r.status_code == 200
        item = r.json()["results"][0]
        assert item["status"] == "ok"
        next_calls = item["cve"]["next_calls"]
        tools = [hint["tool"] for hint in next_calls]
        assert "exploit_lookup" in tools
        assert "kev_detail" in tools
        assert "cwe_lookup" in tools

    @patch("cve.routes.aget_cve", new_callable=AsyncMock, return_value=None)
    def test_bulk_cve_not_found(self, mock_get):
        r = client.post("/v1/cves/bulk", json={"cve_ids": ["CVE-9999-99999"]})
        assert r.status_code == 200
        data = r.json()
        assert data["successful"] == 0
        assert data["results"][0]["status"] == "not_found"

    @patch("cve.routes.aget_cve", new_callable=AsyncMock)
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
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 1
        assert data["successful"] == 0
        assert data["failed"] == 1
        assert data["partial"] is True
        assert data["results"][0]["status"] == "invalid_format"
        assert data["results"][0]["error"] is not None

    def test_cve_get_domain_hint_echo_sanitized(self):
        """Single GET /v1/cve/{id} where id has '.' but no CVE prefix → echo must be sanitized.

        URL-encoded CRLF + HTML + bidi reach the route handler decoded; the error response
        must strip them via sanitize_echo() before f-string interpolation.
        """
        # %0d%0a = CRLF, %3C = '<', %E2%80%AE = U+202E (Trojan-Source bidi)
        path = "/v1/cve/evil.com%0d%0aINJECT%3Cscript%3E%E2%80%AE"
        r = client.get(path)
        assert r.status_code == 400
        detail = r.json()["error"]["message"]
        assert "\r" not in detail
        assert "\n" not in detail
        assert "<" not in detail
        assert "‮" not in detail

    def test_bulk_cve_invalid_format_echo_sanitized(self):
        """Pre-existing surface fixed alongside v1.27 CRITICAL: invalid CVE id echoed in
        results[].cve_id must not carry CRLF / Trojan-Source / HTML payloads."""
        # CRLF + bidi + HTML chars (after .upper(): all printable except CRLF/bidi)
        evil = "CVE-1\r\nINJECT<script>‮"
        r = client.post("/v1/cves/bulk", json={"cve_ids": [evil]})
        assert r.status_code == 200
        item = r.json()["results"][0]
        assert item["status"] == "invalid_format"
        assert "\r" not in item["cve_id"]
        assert "\n" not in item["cve_id"]
        assert "<" not in item["cve_id"]
        assert "‮" not in item["cve_id"]
        assert "<" not in item["error"]
        assert "\n" not in item["error"]

    @patch("cve.routes.aget_cve", new_callable=AsyncMock)
    def test_bulk_cve_truncates_affected_products_by_default(self, mock_get):
        large_cve = dict(self._MOCK_CVE)
        large_cve["affected_products"] = [{"vendor": f"v{i}", "product": f"p{i}"} for i in range(50)]
        mock_get.return_value = large_cve
        r = client.post("/v1/cves/bulk", json={"cve_ids": ["CVE-2024-3094"]})
        assert r.status_code == 200
        data = r.json()
        assert data["successful"] == 1
        cve = data["results"][0]["cve"]
        assert len(cve["affected_products"]) == 20
        assert cve["total_products"] == 50

    @patch("cve.routes.aget_cve", new_callable=AsyncMock)
    def test_bulk_cve_include_affected_products_returns_full(self, mock_get):
        large_cve = dict(self._MOCK_CVE)
        large_cve["affected_products"] = [{"vendor": f"v{i}", "product": f"p{i}"} for i in range(50)]
        mock_get.return_value = large_cve
        r = client.post(
            "/v1/cves/bulk",
            json={"cve_ids": ["CVE-2024-3094"], "include_affected_products": True},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["successful"] == 1
        cve = data["results"][0]["cve"]
        assert len(cve["affected_products"]) == 50
        assert cve["total_products"] == 50

    @patch("cve.routes.aget_cve", new_callable=AsyncMock)
    def test_bulk_cve_truncates_references_to_10_by_default(self, mock_get):
        big = dict(self._MOCK_CVE)
        big["refs"] = [f"https://example.com/r-{i}" for i in range(25)]
        mock_get.return_value = big
        r = client.post("/v1/cves/bulk", json={"cve_ids": ["CVE-2024-3094"]})
        assert r.status_code == 200
        cve = r.json()["results"][0]["cve"]
        assert len(cve["references"]) == 10
        assert cve["total_references"] == 25

    @patch("cve.routes.aget_cve", new_callable=AsyncMock)
    def test_bulk_cve_include_full_references_returns_full(self, mock_get):
        big = dict(self._MOCK_CVE)
        big["refs"] = [f"https://example.com/r-{i}" for i in range(25)]
        mock_get.return_value = big
        r = client.post(
            "/v1/cves/bulk",
            json={"cve_ids": ["CVE-2024-3094"], "include_full_references": True},
        )
        assert r.status_code == 200
        cve = r.json()["results"][0]["cve"]
        assert len(cve["references"]) == 25
        assert cve["total_references"] == 25

    def test_bulk_cve_empty_list(self):
        """v1.21.0 parity: empty list → 200 + empty results (matches bulk_atlas + bulk_ioc)."""
        r = client.post("/v1/cves/bulk", json={"cve_ids": []})
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 0
        assert data["results"] == []
        assert data["successful"] == 0
        assert data["partial"] is False

    @patch("cve.routes.aget_cve", new_callable=AsyncMock)
    def test_bulk_cve_partial_fill_when_quota_low(self, mock_get):
        """v1.27: when remaining quota < input list, surplus lands in skipped_due_to_rate_limit."""
        mock_get.return_value = dict(self._MOCK_CVE)
        # Free tier with only 2 quota units left → can process 3 ids total.
        auth_ctx = __import__("auth").AuthCtx(
            tier="free",
            key_hash=None,
            client_ip="127.0.0.1",
            ratelimit_limit=100,
            ratelimit_remaining=2,
            ratelimit_reset=0,
            ratelimit_cost=1,
        )
        ids = [f"CVE-2024-{i:05d}" for i in range(8)]
        with patch("auth.aauthenticate", new_callable=AsyncMock, return_value=auth_ctx):
            r = client.post("/v1/cves/bulk", json={"cve_ids": ids})
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 8
        assert data["processed"] == 3
        assert data["skipped_due_to_rate_limit"] == ids[3:]
        assert data["partial"] is True

    def test_bulk_cve_over_max_limit(self):
        ids = [f"CVE-2024-{i:05d}" for i in range(51)]
        r = client.post("/v1/cves/bulk", json={"cve_ids": ids})
        assert r.status_code == 422

    @patch("ratelimit.consume_bulk", return_value=False)
    @patch(
        "auth.aauthenticate",
        new_callable=AsyncMock,
        return_value=__import__("auth").AuthCtx(
            tier="free",
            key_hash=None,
            client_ip="127.0.0.1",
            ratelimit_limit=100,
            ratelimit_remaining=99,
            ratelimit_reset=0,
            ratelimit_cost=1,
        ),
    )
    def test_bulk_cve_consume_bulk_race_falls_back_to_one(self, mock_auth, mock_consume):
        """v1.27: when aconsume_bulk loses the race, partial-fill processes 1 (the require_auth payment)
        and surfaces the rest as skipped — no 429 for the batch."""
        ids = [f"CVE-2024-{i:05d}" for i in range(5)]
        r = client.post("/v1/cves/bulk", json={"cve_ids": ids})
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 5
        assert data["processed"] == 1
        assert len(data["skipped_due_to_rate_limit"]) == 4
        # Verify consume_bulk was attempted with extra = processable - 1 = 4
        mock_consume.assert_called_once()
        args = mock_consume.call_args.args
        assert args[0] == "api"
        assert args[2] == 4

    @patch("cve.routes.aget_cve", new_callable=AsyncMock)
    def test_bulk_cve_deduplicates(self, mock_get):
        mock_get.return_value = dict(self._MOCK_CVE)
        r = client.post("/v1/cves/bulk", json={"cve_ids": ["CVE-2024-3094", "CVE-2024-3094"]})
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 1

    def test_bulk_cve_patch_available_enriched(self):
        """Bulk path must populate patch_available like single cve_lookup (parity guard)."""
        _seed_cve(
            cve_id="CVE-2024-9101",
            refs=["https://github.com/advisories/GHSA-bulk-1111-test"],
        )
        r = client.post("/v1/cves/bulk", json={"cve_ids": ["CVE-2024-9101"]})
        assert r.status_code == 200
        cve = r.json()["results"][0]["cve"]
        assert cve["patch_available"] is True
        assert cve["patch_url"] == "https://github.com/advisories/GHSA-bulk-1111-test"

    def test_bulk_cve_related_cves_enriched(self):
        """Bulk path must populate related_cves like single cve_lookup (parity guard)."""
        _seed_cve(
            cve_id="CVE-2024-9201",
            severity="HIGH",
            cvss_v3=8.0,
            affected_products=[{"vendor": "acme", "product": "bulkparityprod"}],
        )
        _seed_cve(
            cve_id="CVE-2024-9202",
            severity="CRITICAL",
            cvss_v3=9.5,
            affected_products=[{"vendor": "acme", "product": "bulkparityprod"}],
        )
        r = client.post("/v1/cves/bulk", json={"cve_ids": ["CVE-2024-9201"]})
        assert r.status_code == 200
        cve = r.json()["results"][0]["cve"]
        assert cve["related_cves"], "bulk should return related_cves, not null"
        cve_ids = [r["cve_id"] for r in cve["related_cves"]]
        assert "CVE-2024-9202" in cve_ids
        assert "CVE-2024-9201" not in cve_ids  # excludes self

    def test_bulk_cve_parity_with_single_lookup(self):
        """Same CVE through /v1/cve/{id} and /v1/cves/bulk must yield equivalent enrichment."""
        _seed_cve(
            cve_id="CVE-2024-9301",
            severity="CRITICAL",
            cvss_v3=9.8,
            affected_products=[{"vendor": "acme", "product": "parityprod"}],
            refs=["https://github.com/advisories/GHSA-parity-2222-test"],
        )
        _seed_cve(
            cve_id="CVE-2024-9302",
            severity="HIGH",
            cvss_v3=7.5,
            affected_products=[{"vendor": "acme", "product": "parityprod"}],
        )
        single = client.get("/v1/cve/CVE-2024-9301").json()
        bulk = client.post("/v1/cves/bulk", json={"cve_ids": ["CVE-2024-9301"]}).json()
        bulk_cve = bulk["results"][0]["cve"]
        for field in ("patch_available", "patch_url", "related_cves"):
            assert single.get(field) == bulk_cve.get(field), (
                f"{field} drift: single={single.get(field)!r} bulk={bulk_cve.get(field)!r}"
            )

    def test_bulk_cve_format_edge_cases(self):
        """Various malformed CVE IDs should return 200 with per-item invalid_format."""
        bad_ids = [
            "CVE-2024-",  # missing number
            "CVE--12345",  # missing year
            "CVE-2024",  # missing dash and number
            "ABC-2024-12345",  # wrong prefix
        ]
        for bad in bad_ids:
            r = client.post("/v1/cves/bulk", json={"cve_ids": [bad]})
            assert r.status_code == 200, f"Expected 200 for {bad!r}, got {r.status_code}"
            data = r.json()
            assert data["results"][0]["status"] == "invalid_format"
            assert data["results"][0]["error"] is not None
            assert data["partial"] is True

    @patch("cve.routes.aget_cve", new_callable=AsyncMock)
    def test_bulk_cve_mixed_valid_invalid_format(self, mock_get):
        """Valid + invalid-format IDs in same batch → 200 OK with per-item status."""
        mock_get.return_value = dict(self._MOCK_CVE)
        r = client.post(
            "/v1/cves/bulk",
            json={"cve_ids": ["CVE-2024-3094", "NOT-A-CVE", "CVE-2021-44228"]},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 3
        assert data["successful"] == 2
        assert data["failed"] == 1
        assert data["partial"] is True
        statuses = {r["status"] for r in data["results"]}
        assert statuses == {"ok", "invalid_format"}
        invalid = [r for r in data["results"] if r["status"] == "invalid_format"]
        assert len(invalid) == 1
        assert invalid[0]["cve_id"] == "NOT-A-CVE"
        assert invalid[0]["error"] is not None

    @patch("cve.routes.aget_cve", new_callable=AsyncMock)
    def test_bulk_cve_partial_flag_false_when_all_ok(self, mock_get):
        """partial=False only when every item is status=ok."""
        mock_get.return_value = dict(self._MOCK_CVE)
        r = client.post("/v1/cves/bulk", json={"cve_ids": ["CVE-2024-3094"]})
        assert r.status_code == 200
        data = r.json()
        assert data["partial"] is False
        assert data["failed"] == 0
        assert data["timed_out"] == 0

    @patch("cve.routes.aget_cve", new_callable=AsyncMock, return_value=None)
    def test_bulk_cve_mixed_invalid_and_not_found(self, mock_get):
        """invalid_format + not_found statuses coexist in one response."""
        r = client.post(
            "/v1/cves/bulk",
            json={"cve_ids": ["CVE-9999-99999", "NOT-A-CVE"]},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["successful"] == 0
        assert data["failed"] == 2
        assert data["partial"] is True
        statuses = {r["status"] for r in data["results"]}
        assert statuses == {"not_found", "invalid_format"}

    def test_bulk_cve_item_length_cap(self):
        """Oversized per-item CVE ID (>64 chars) rejected by schema before dispatch."""
        r = client.post(
            "/v1/cves/bulk",
            json={"cve_ids": ["CVE-2024-" + "9" * 100]},
        )
        assert r.status_code == 422

    @patch("cve.routes.aget_cve_sources", new_callable=AsyncMock)
    @patch("cve.routes.aget_cve", new_callable=AsyncMock)
    def test_bulk_cve_results_include_verdict(self, mock_get, mock_sources):
        mock_get.return_value = dict(self._MOCK_CVE)
        mock_sources.return_value = [
            {"source": "nvd", "first_seen_at": "2024-01-01T00:00:00Z"},
            {"source": "ghsa", "first_seen_at": "2024-01-02T00:00:00Z"},
        ]
        r = client.post("/v1/cves/bulk", json={"cve_ids": ["CVE-2024-3094"]})
        assert r.status_code == 200
        data = r.json()
        item = data["results"][0]
        assert item["status"] == "ok"
        verdict = item["cve"]["verdict"]
        assert verdict is not None
        assert verdict["deterministic"] is True
        # _MOCK_CVE has refs=[] → BUG-VER-4: non-minimal + empty refs → "partial"
        assert verdict["completeness"] == "partial"
        assert verdict["sources_queried"] == ["nvd_cache", "ghsa_cache"]

    @patch("cve.routes.aget_cve_sources", new_callable=AsyncMock)
    @patch("cve.routes.aget_cve", new_callable=AsyncMock)
    def test_bulk_cve_minimal_empty_sources_returns_empty_sources_queried(self, mock_get, mock_sources):
        stub = {k: v for k, v in self._MOCK_CVE.items() if k not in {"severity", "cvss_v3", "description"}}
        mock_get.return_value = stub
        mock_sources.return_value = []
        r = client.post("/v1/cves/bulk", json={"cve_ids": ["CVE-2024-3094"]})
        assert r.status_code == 200
        verdict = r.json()["results"][0]["cve"]["verdict"]
        assert verdict["completeness"] == "minimal"
        assert verdict["sources_queried"] == []

    def test_bulk_cve_invalid_format_omits_verdict(self):
        r = client.post("/v1/cves/bulk", json={"cve_ids": ["NOT-A-CVE"]})
        assert r.status_code == 200
        data = r.json()
        item = data["results"][0]
        assert item["status"] == "invalid_format"
        assert item.get("cve") is None
        assert "verdict" not in item


class TestBatch2CacheVerdictRefresh:
    """Batch 2: verdict.data_age_seconds must drift on cache hit (not freeze),
    and cve_leading/kev_detail/cwe_lookup must serve from cache on second call."""

    def _patch_nvd_age(self, frozen_iso: str):
        """Helper: patch aget_last_successful_sync('nvd') to return a fixed timestamp."""
        from unittest.mock import patch as _patch

        async def _fake(source: str):
            if source == "nvd":
                return frozen_iso
            return None

        return _patch("cve.routes.aget_last_successful_sync", new=_fake)

    def test_cve_lookup_verdict_data_age_recomputed_on_cache_hit(self):
        # First call captures NVD sync at T0; second call (cache hit) must
        # recompute data_age_seconds against a NEWER NVD sync timestamp,
        # i.e. the cached response must NOT serve a frozen verdict.
        from datetime import UTC, datetime, timedelta

        _seed_cve(cve_id="CVE-2024-44001")
        t0 = datetime.now(UTC) - timedelta(seconds=200)
        t1 = datetime.now(UTC) - timedelta(seconds=10)
        with self._patch_nvd_age(t0.isoformat()):
            r1 = client.get("/v1/cve/CVE-2024-44001")
        assert r1.status_code == 200
        age1 = r1.json()["verdict"]["data_age_seconds"]
        assert 195 <= age1 <= 210, f"cold-call age was {age1}"
        with self._patch_nvd_age(t1.isoformat()):
            r2 = client.get("/v1/cve/CVE-2024-44001")
        assert r2.status_code == 200
        age2 = r2.json()["verdict"]["data_age_seconds"]
        assert 5 <= age2 <= 20, f"hot-call age was {age2} - verdict appears frozen"

    def test_cve_search_verdict_data_age_recomputed_on_cache_hit(self):
        from datetime import UTC, datetime, timedelta

        _seed_cve(cve_id="CVE-2024-44002", severity="HIGH")
        t0 = datetime.now(UTC) - timedelta(seconds=180)
        t1 = datetime.now(UTC) - timedelta(seconds=5)
        with self._patch_nvd_age(t0.isoformat()):
            r1 = client.get("/v1/cves?severity=HIGH&limit=3&offset=900")
        assert r1.status_code == 200
        age1 = r1.json()["verdict"]["data_age_seconds"]
        assert 175 <= age1 <= 195, f"cold age was {age1}"
        with self._patch_nvd_age(t1.isoformat()):
            r2 = client.get("/v1/cves?severity=HIGH&limit=3&offset=900")
        assert r2.status_code == 200
        age2 = r2.json()["verdict"]["data_age_seconds"]
        assert 0 <= age2 <= 15, f"hot-call age was {age2} - verdict appears frozen"

    def test_exploit_lookup_verdict_data_age_recomputed_on_cache_hit(self):
        # exploit_lookup verdict.data_age_seconds derives from max of
        # github_advisory, shodan_cvedb, exploitdb sync ages (BUG-VER-2 post-Batch-3A).
        # github + shodan have no sync_status entry in production -> None.
        # Source-aware mock: yield iter values for "exploitdb", None otherwise.
        from unittest.mock import patch as _patch

        ages = iter([300, 12])

        async def _fake_age(source: str):
            if source == "exploitdb":
                return next(ages)
            return None

        gh_resp = MagicMock()
        gh_resp.status_code = 200
        gh_resp.json.return_value = []
        gh_resp.raise_for_status = MagicMock()

        with (
            _patch("cve.routes._exploit_client.get", new_callable=AsyncMock, return_value=gh_resp),
            _patch("cve.routes._sync_age_seconds", new=_fake_age),
        ):
            r1 = client.get("/v1/exploit/CVE-2024-44003")
            assert r1.status_code == 200
            age1 = r1.json()["verdict"]["data_age_seconds"]
            assert age1 == 300, f"cold age was {age1}"
            r2 = client.get("/v1/exploit/CVE-2024-44003")
            assert r2.status_code == 200
            age2 = r2.json()["verdict"]["data_age_seconds"]
            assert age2 == 12, f"hot-call age was {age2} - verdict appears frozen"

    def test_cve_leading_second_call_served_from_cache(self):
        from unittest.mock import patch as _patch

        _seed_cve(cve_id="CVE-2024-LEADCACHE1")
        with _patch(
            "cve.routes.aget_leading_cves", new_callable=AsyncMock, wraps=__import__("db").aget_leading_cves
        ) as spy:
            r1 = client.get("/v1/cve/leading?limit=5&offset=0")
            assert r1.status_code == 200
            r2 = client.get("/v1/cve/leading?limit=5&offset=0")
            assert r2.status_code == 200
            assert spy.call_count == 1, f"hot call must short-circuit; spy fired {spy.call_count}x"

    def test_cve_leading_cache_segregates_by_include(self):
        from unittest.mock import patch as _patch

        _seed_cve(cve_id="CVE-2024-LEADCACHE2")
        with _patch(
            "cve.routes.aget_leading_cves", new_callable=AsyncMock, wraps=__import__("db").aget_leading_cves
        ) as spy:
            client.get("/v1/cve/leading?limit=5&offset=0")
            client.get("/v1/cve/leading?limit=5&offset=0&include=full")
            assert spy.call_count == 2, "slim and full must NOT share a cache entry"

    def test_kev_detail_second_call_served_from_cache(self):
        from unittest.mock import patch as _patch

        from db import upsert_kev_details

        _seed_cve(cve_id="CVE-2024-44004", in_kev=1)
        upsert_kev_details(
            "CVE-2024-44004",
            vendor_project="acme",
            product="widget",
            vulnerability_name="Acme Widget RCE",
            due_date="2024-06-21",
            required_action="Patch",
            known_ransomware_use=False,
            notes="",
            cwes=["CWE-79"],
        )
        with _patch(
            "cve.routes.aget_kev_details", new_callable=AsyncMock, wraps=__import__("db").aget_kev_details
        ) as spy:
            r1 = client.get("/v1/kev/CVE-2024-44004")
            assert r1.status_code == 200
            r2 = client.get("/v1/kev/CVE-2024-44004")
            assert r2.status_code == 200
            assert spy.call_count == 1, f"hot call must short-circuit; spy fired {spy.call_count}x"

    def test_cwe_lookup_second_call_served_from_cache(self):
        from unittest.mock import patch as _patch

        from db import upsert_cwe

        upsert_cwe(
            "CWE-9991",
            name="Test Weakness",
            description="A weakness for cache testing.",
            abstract_type="Base",
            status="Stable",
            likelihood="Medium",
            mitigations=[],
            examples=[],
            parent_cwe=None,
            child_cwes=[],
        )
        with _patch("cve.routes.aget_cwe", new_callable=AsyncMock, wraps=__import__("db").aget_cwe) as spy:
            r1 = client.get("/v1/cwe/CWE-9991")
            assert r1.status_code == 200
            r2 = client.get("/v1/cwe/CWE-9991")
            assert r2.status_code == 200
            assert spy.call_count == 1, f"hot call must short-circuit; spy fired {spy.call_count}x"

    def test_cwe_lookup_cache_segregates_by_include(self):
        from unittest.mock import patch as _patch

        from db import upsert_cwe

        upsert_cwe(
            "CWE-9992",
            name="Test Weakness Two",
            description="Another test weakness.",
            extended_description="Long description...",
            abstract_type="Base",
            status="Stable",
            likelihood="Low",
            mitigations=[],
            examples=[],
            parent_cwe=None,
            child_cwes=[],
        )
        with _patch("cve.routes.aget_cwe", new_callable=AsyncMock, wraps=__import__("db").aget_cwe) as spy:
            client.get("/v1/cwe/CWE-9992")
            client.get("/v1/cwe/CWE-9992?include=full")
            assert spy.call_count == 2, "slim and full must NOT share a cache entry"

    def test_bulk_cve_lookup_per_item_verdict_is_dict(self):
        # bulk routes.py:1342 was assigning a Pydantic model to formatted["verdict"];
        # every other call site uses .model_dump(). Assert wire output is a plain dict.
        _seed_cve(cve_id="CVE-2024-44005")
        r = client.post("/v1/cves/bulk", json={"cve_ids": ["CVE-2024-44005"]})
        assert r.status_code == 200
        item = r.json()["results"][0]
        assert isinstance(item["cve"]["verdict"], dict)
        assert "completeness" in item["cve"]["verdict"]


class TestBatch3VerdictHonesty:
    """Batch 3A: verdict.falsifiable_fields must be filtered by populated fields,
    completeness must degrade on empty sources/refs, exploit data_age = max of 3 syncs,
    kev_detail/cwe_lookup data_age must reflect their own sync (not NVD),
    cve_leading must populate next_offset and detect stale upstream syncs."""

    def test_falsifiable_excludes_null_severity(self):
        # BUG-7: when severity is null in the formatted CVE, it must NOT appear
        # in falsifiable_fields. Plan: dynamic populated-only filter.
        _seed_cve(cve_id="CVE-2024-99901", severity=None, cvss_v3=None)
        r = client.get("/v1/cve/CVE-2024-99901")
        assert r.status_code == 200
        ff = r.json()["verdict"]["falsifiable_fields"]
        assert "severity" not in ff, f"severity should be filtered when null; got {ff}"
        assert "cvss_v3" not in ff, f"cvss_v3 should be filtered when null; got {ff}"
        assert "cve_id" in ff, f"cve_id always populated; got {ff}"

    def test_falsifiable_includes_modified_when_populated(self):
        # BUG-VER-5: "modified" field should appear in falsifiable_fields when populated.
        _seed_cve(cve_id="CVE-2024-99902", modified="2024-08-15T00:00:00Z")
        r = client.get("/v1/cve/CVE-2024-99902")
        assert r.status_code == 200
        ff = r.json()["verdict"]["falsifiable_fields"]
        assert "modified" in ff, f"modified should be in falsifiable_fields when populated; got {ff}"

    def test_completeness_partial_when_references_empty_non_minimal(self):
        # BUG-VER-4: refs=[] + non-minimal (has severity/cvss/description) → "partial"
        _seed_cve(
            cve_id="CVE-2024-99903",
            severity="HIGH",
            cvss_v3=8.5,
            description="A vulnerability.",
            refs=[],
        )
        r = client.get("/v1/cve/CVE-2024-99903")
        assert r.status_code == 200
        completeness = r.json()["verdict"]["completeness"]
        assert completeness == "partial", f"empty refs non-minimal -> partial; got {completeness}"

    def test_exploit_data_age_max_of_three_syncs(self):
        # BUG-VER-2: data_age_seconds = max of github_advisory, shodan_cvedb, exploitdb.
        # github + shodan have no sync_status row in production -> _sync_age_seconds returns None.
        # max() must pick exploitdb_age and not crash on None.
        from unittest.mock import patch as _patch

        async def _fake_age(source: str):
            if source == "exploitdb":
                return 4242
            return None  # github_advisory, shodan_cvedb live API, no sync_status

        gh_resp = MagicMock()
        gh_resp.status_code = 200
        gh_resp.json.return_value = []
        gh_resp.raise_for_status = MagicMock()

        with (
            _patch("cve.routes._exploit_client.get", new_callable=AsyncMock, return_value=gh_resp),
            _patch("cve.routes._sync_age_seconds", new=_fake_age),
        ):
            r = client.get("/v1/exploit/CVE-2024-99904")
            assert r.status_code == 200
            assert r.json()["verdict"]["data_age_seconds"] == 4242

    def test_kev_detail_data_age_uses_kev_sync_not_nvd(self):
        # BUG-VER-3: kev_detail must read aget_last_successful_sync("kev"), not "nvd".
        from datetime import UTC, datetime, timedelta
        from unittest.mock import patch as _patch

        from db import upsert_kev_details

        _seed_cve(cve_id="CVE-2024-99905", in_kev=1)
        upsert_kev_details(
            "CVE-2024-99905",
            vendor_project="acme",
            product="widget",
            vulnerability_name="Acme Widget RCE",
            due_date="2024-06-21",
            required_action="Patch",
            known_ransomware_use=False,
            notes="",
            cwes=["CWE-79"],
        )
        kev_ts = (datetime.now(UTC) - timedelta(seconds=500)).isoformat()
        nvd_ts = (datetime.now(UTC) - timedelta(seconds=99999)).isoformat()

        async def _fake(source: str):
            if source == "kev":
                return kev_ts
            if source == "nvd":
                return nvd_ts
            return None

        with _patch("cve.routes.aget_last_successful_sync", new=_fake):
            r = client.get("/v1/kev/CVE-2024-99905")
        assert r.status_code == 200
        age = r.json()["verdict"]["data_age_seconds"]
        # Must reflect KEV sync (~500s), NOT NVD sync (~99999s)
        assert 480 <= age <= 520, f"data_age must come from KEV sync, got {age}"

    def test_cwe_lookup_data_age_uses_cwe_sync_not_nvd(self):
        # BUG-VER-3: cwe_lookup must read aget_last_successful_sync("cwe"), not "nvd".
        from datetime import UTC, datetime, timedelta
        from unittest.mock import patch as _patch

        from db import upsert_cwe

        upsert_cwe(
            "CWE-9993",
            name="Test Weakness Three",
            description="Cwe age test.",
            abstract_type="Base",
            status="Stable",
            likelihood="Medium",
            mitigations=[],
            examples=[],
            parent_cwe=None,
            child_cwes=[],
        )
        cwe_ts = (datetime.now(UTC) - timedelta(seconds=400)).isoformat()
        nvd_ts = (datetime.now(UTC) - timedelta(seconds=88888)).isoformat()

        async def _fake(source: str):
            if source == "cwe":
                return cwe_ts
            if source == "nvd":
                return nvd_ts
            return None

        with _patch("cve.routes.aget_last_successful_sync", new=_fake):
            r = client.get("/v1/cwe/CWE-9993")
        assert r.status_code == 200
        age = r.json()["verdict"]["data_age_seconds"]
        assert 380 <= age <= 420, f"data_age must come from CWE sync, got {age}"

    def test_cve_leading_next_offset_populated(self):
        # BUG-DOC-3 (route side): cve_leading response must include next_offset
        # when truncated (offset + count < total).
        for i in range(10):
            _seed_cve(cve_id=f"CVE-2024-9981{i}", cvss_v3=None, severity=None)
        r = client.get("/v1/cve/leading?limit=2&offset=0")
        assert r.status_code == 200
        body = r.json()
        if body["truncated"]:
            assert body.get("next_offset") == 2, f"next_offset should be offset+count=2; got {body.get('next_offset')}"
        else:
            assert "next_offset" in body or body.get("next_offset") is None

    def test_cve_leading_next_offset_null_on_last_page(self):
        # When not truncated, next_offset must be null (or absent due to exclude_none).
        r = client.get("/v1/cve/leading?limit=200&offset=0")
        assert r.status_code == 200
        body = r.json()
        if not body["truncated"]:
            assert body.get("next_offset") is None

    def test_cve_leading_sources_unavailable_when_mitre_stale(self):
        # BUG-VER-1: when mitre sync is >7 days old, "mitre_cache" must appear
        # in verdict.sources_unavailable.
        from datetime import UTC, datetime, timedelta
        from unittest.mock import patch as _patch

        stale_ts = (datetime.now(UTC) - timedelta(days=8)).isoformat()
        fresh_ts = (datetime.now(UTC) - timedelta(seconds=300)).isoformat()

        async def _fake(source: str):
            if source == "mitre":
                return stale_ts
            if source == "ghsa":
                return fresh_ts
            if source == "nvd":
                return fresh_ts
            return None

        with _patch("cve.routes.aget_last_successful_sync", new=_fake):
            r = client.get("/v1/cve/leading?limit=5&offset=0&include=full")
        assert r.status_code == 200
        unavailable = r.json()["verdict"].get("sources_unavailable") or []
        assert "mitre_cache" in unavailable, f"stale mitre must populate sources_unavailable; got {unavailable}"
        assert "ghsa_cache" not in unavailable, f"fresh ghsa must NOT be unavailable; got {unavailable}"

    def test_cve_leading_data_age_uses_mitre_sync_not_nvd(self):
        # BUG-VER-3: cve_leading primary_source="mitre" -- data_age reflects mitre sync.
        from datetime import UTC, datetime, timedelta
        from unittest.mock import patch as _patch

        mitre_ts = (datetime.now(UTC) - timedelta(seconds=600)).isoformat()
        nvd_ts = (datetime.now(UTC) - timedelta(seconds=77777)).isoformat()

        async def _fake(source: str):
            if source == "mitre":
                return mitre_ts
            if source == "nvd":
                return nvd_ts
            if source == "ghsa":
                return mitre_ts
            return None

        with _patch("cve.routes.aget_last_successful_sync", new=_fake):
            r = client.get("/v1/cve/leading?limit=5&offset=0")
        assert r.status_code == 200
        age = r.json()["verdict"]["data_age_seconds"]
        assert 580 <= age <= 620, f"data_age must come from mitre sync, got {age}"


class TestBatch4AMultiCwe:
    """Batch 4A — multi-CWE end-to-end (NVD parser primary/secondary, KEV view-ID filter,
    schema field, _format_cve emit, _cve_pivot_hints multi-pivot, migration backfill)."""

    def test_nvd_parser_extracts_cpe_part_and_vulnerable_flag(self):
        """batch g v1.30.0: NVD parser captures CPE part (a/o/h) and the vulnerable
        flag from each cpeMatch — search filter then ignores target_sw rows."""
        from cve.sync import _parse_nvd_cve

        item = {
            "cve": {
                "id": "CVE-2024-CPE1",
                "descriptions": [],
                "metrics": {},
                "weaknesses": [],
                "references": [],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "criteria": "cpe:2.3:a:google:chrome:120.0.0:*:*:*:*:*:*:*",
                                        "vulnerable": True,
                                    },
                                    {
                                        "criteria": "cpe:2.3:o:linus:linux_kernel:6.0:*:*:*:*:*:*:*",
                                        "vulnerable": False,
                                    },
                                    {
                                        "criteria": "cpe:2.3:h:cisco:asa_5500:1.0:*:*:*:*:*:*:*",
                                        "vulnerable": True,
                                    },
                                ]
                            }
                        ]
                    }
                ],
            }
        }
        result = _parse_nvd_cve(item)
        by_product = {p["product"]: p for p in result["affected_products"]}
        assert by_product["chrome"]["cpe_part"] == "a"
        assert by_product["chrome"]["vulnerable"] is True
        assert by_product["linux_kernel"]["cpe_part"] == "o"
        assert by_product["linux_kernel"]["vulnerable"] is False
        assert by_product["asa_5500"]["cpe_part"] == "h"
        assert by_product["asa_5500"]["vulnerable"] is True

    def test_nvd_parser_vulnerable_defaults_true_when_missing(self):
        """batch g v1.30.0: when NVD omits the vulnerable flag, default to True
        (back-compat with older feed shapes)."""
        from cve.sync import _parse_nvd_cve

        item = {
            "cve": {
                "id": "CVE-2024-CPE2",
                "descriptions": [],
                "metrics": {},
                "weaknesses": [],
                "references": [],
                "configurations": [
                    {"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:vendor:legacy_app:1.0:*:*:*:*:*:*:*"}]}]}
                ],
            }
        }
        result = _parse_nvd_cve(item)
        assert result["affected_products"][0]["vulnerable"] is True
        assert result["affected_products"][0]["cpe_part"] == "a"

    def test_nvd_parser_picks_primary_cwe_first(self):
        """NVD weaknesses[].type=Primary CWE must come first in cwes; cwe_id=primary."""
        from cve.sync import _parse_nvd_cve

        item = {
            "cve": {
                "id": "CVE-2024-21626",
                "descriptions": [{"lang": "en", "value": "runc escape"}],
                "metrics": {},
                "weaknesses": [
                    {
                        "source": "security-advisories@github.com",
                        "type": "Secondary",
                        "description": [
                            {"lang": "en", "value": "CWE-403"},
                            {"lang": "en", "value": "CWE-668"},
                        ],
                    },
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [{"lang": "en", "value": "CWE-668"}],
                    },
                ],
                "references": [],
                "configurations": [],
            }
        }
        result = _parse_nvd_cve(item)
        assert result["cwe_id"] == "CWE-668", "Primary CWE must be picked, not Secondary"
        assert result["cwes"] == ["CWE-668", "CWE-403"], (
            f"Primary first, Secondary next, deduped — got {result['cwes']!r}"
        )

    def test_nvd_parser_filters_view_id_cwes(self):
        """NVD view-ID CWEs (699/1000/1003) must NOT appear in cwes."""
        from cve.sync import _parse_nvd_cve

        item = {
            "cve": {
                "id": "CVE-2024-9001",
                "descriptions": [],
                "metrics": {},
                "weaknesses": [
                    {
                        "type": "Primary",
                        "description": [
                            {"lang": "en", "value": "CWE-79"},
                            {"lang": "en", "value": "CWE-1000"},
                            {"lang": "en", "value": "CWE-699"},
                            {"lang": "en", "value": "CWE-1003"},
                        ],
                    }
                ],
                "references": [],
            }
        }
        result = _parse_nvd_cve(item)
        assert result["cwe_id"] == "CWE-79"
        assert result["cwes"] == ["CWE-79"], f"view-ID CWEs (699/1000/1003) must be filtered — got {result['cwes']!r}"

    def test_nvd_parser_no_cwe_returns_none(self):
        """Empty weaknesses → cwe_id=None and cwes=[]."""
        from cve.sync import _parse_nvd_cve

        item = {
            "cve": {
                "id": "CVE-2024-9002",
                "descriptions": [],
                "metrics": {},
                "weaknesses": [],
                "references": [],
            }
        }
        result = _parse_nvd_cve(item)
        assert result["cwe_id"] is None
        assert result["cwes"] == []

    def test_nvd_parser_only_secondary_falls_back(self):
        """When NO Primary weakness exists, first Secondary CWE is selected for cwe_id."""
        from cve.sync import _parse_nvd_cve

        item = {
            "cve": {
                "id": "CVE-2024-9003",
                "descriptions": [],
                "metrics": {},
                "weaknesses": [
                    {
                        "type": "Secondary",
                        "description": [{"lang": "en", "value": "CWE-352"}],
                    }
                ],
                "references": [],
            }
        }
        result = _parse_nvd_cve(item)
        assert result["cwe_id"] == "CWE-352"
        assert result["cwes"] == ["CWE-352"]

    @patch("cve.sync._client", new_callable=AsyncMock)
    def test_kev_sync_filters_view_id_cwes(self, mock_client):
        """KEV feed view-ID CWEs must be filtered out of kev_details.cwes."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-3030",
                    "dateAdded": "2024-03-01",
                    "cwes": ["CWE-787", "CWE-1000", "CWE-699", "CWE-1003"],
                }
            ]
        }
        mock_resp.raise_for_status.return_value = None
        mock_client.get.return_value = mock_resp

        from cve.sync import sync_kev
        from db import get_kev_details

        asyncio.run(sync_kev())
        details = get_kev_details("CVE-2024-3030")
        assert details is not None
        assert details["cwes"] == ["CWE-787"], f"view-ID CWEs must be dropped — got {details['cwes']!r}"

    def test_format_cve_emits_cwes_field(self):
        """cve_lookup response must carry both cwe_id (primary) and cwes (array)."""
        _seed_cve(
            cve_id="CVE-2024-4001",
            cwe_id="CWE-502",
            cwes=["CWE-502", "CWE-917", "CWE-20"],
        )
        r = client.get("/v1/cve/CVE-2024-4001")
        assert r.status_code == 200
        body = r.json()
        assert body["cwe_id"] == "CWE-502"
        assert body["cwes"] == ["CWE-502", "CWE-917", "CWE-20"]

    def test_format_cve_cwes_none_when_absent(self):
        """When cwes column is NULL, response omits the field (response_model_exclude_none)."""
        _seed_cve(cve_id="CVE-2024-4002", cwe_id=None, cwes=None)
        r = client.get("/v1/cve/CVE-2024-4002")
        assert r.status_code == 200
        body = r.json()
        assert "cwes" not in body or body.get("cwes") is None

    def test_lookup_next_calls_emits_max_3_cwe_pivots(self):
        """When CVE has 3+ CWEs, _cve_pivot_hints emits exactly 3 cwe_lookup pivots in order."""
        _seed_cve(
            cve_id="CVE-2024-4003",
            cwe_id="CWE-502",
            cwes=["CWE-502", "CWE-917", "CWE-20", "CWE-94"],
            in_kev=0,
            kev_date_added=None,
        )
        r = client.get("/v1/cve/CVE-2024-4003")
        next_calls = r.json()["next_calls"]
        cwe_pivots = [h for h in next_calls if h["tool"] == "cwe_lookup"]
        assert len(cwe_pivots) == 3, f"max 3 cwe_lookup pivots; got {len(cwe_pivots)}"
        assert [h["input"] for h in cwe_pivots] == ["CWE-502", "CWE-917", "CWE-20"]

    def test_lookup_next_calls_fallback_to_cwe_id_when_cwes_empty(self):
        """Legacy rows without cwes (None) should still emit 1 cwe_lookup pivot from cwe_id."""
        _seed_cve(
            cve_id="CVE-2024-4004",
            cwe_id="CWE-120",
            cwes=None,
            in_kev=0,
            kev_date_added=None,
        )
        r = client.get("/v1/cve/CVE-2024-4004")
        next_calls = r.json()["next_calls"]
        cwe_pivots = [h for h in next_calls if h["tool"] == "cwe_lookup"]
        assert len(cwe_pivots) == 1
        assert cwe_pivots[0]["input"] == "CWE-120"

    def test_lookup_next_calls_omits_cwe_when_no_cwe_data(self):
        """No cwe_id AND no cwes → zero cwe_lookup pivots."""
        _seed_cve(
            cve_id="CVE-2024-4005",
            cwe_id=None,
            cwes=None,
            in_kev=0,
            kev_date_added=None,
        )
        r = client.get("/v1/cve/CVE-2024-4005")
        next_calls = r.json()["next_calls"]
        assert all(h["tool"] != "cwe_lookup" for h in next_calls)

    def test_verdict_falsifiable_fields_includes_cwes_when_populated(self):
        """When cwes is populated, verdict.falsifiable_fields must list 'cwes'."""
        _seed_cve(
            cve_id="CVE-2024-4006",
            cwe_id="CWE-502",
            cwes=["CWE-502", "CWE-917"],
        )
        r = client.get("/v1/cve/CVE-2024-4006")
        body = r.json()
        assert "cwes" in body["verdict"]["falsifiable_fields"], (
            f"falsifiable_fields must include 'cwes' when populated — got {body['verdict']['falsifiable_fields']!r}"
        )

    def test_migration_backfill_populates_cwes_from_cwe_id(self):
        """Migration UPDATE statement: rows with cwe_id but cwes=NULL get cwes=[cwe_id]."""
        from db import get_cve_db

        with get_cve_db() as con:
            con.execute(
                "INSERT INTO cves (cve_id, cwe_id, cwes) VALUES (?, ?, NULL)",
                ("CVE-LEGACY-0001", "CWE-79"),
            )
            con.execute("UPDATE cves SET cwes = json_array(cwe_id) WHERE cwe_id IS NOT NULL AND cwes IS NULL")
            row = con.execute("SELECT cwes FROM cves WHERE cve_id = 'CVE-LEGACY-0001'").fetchone()
        assert json.loads(row[0]) == ["CWE-79"]


class TestBatch4BShodanRefs:
    """Batch 4B — Shodan refs configurable cap (SHODAN_REFS_LIMIT default 200) +
    honest upstream count + truncated bool flag. Mirrors the truncated-flag pattern
    from RobotsResponse / RedirectChainResponse in app/domain/schemas.py."""

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    def test_shodan_refs_truncates_at_default_cap(self, mock_cache_get, mock_cache_save):
        """250 refs upstream + default cap=200 → count=250 (honest), truncated=true, len(results)=200."""
        gh_resp = MagicMock()
        gh_resp.json.return_value = []
        gh_resp.raise_for_status = MagicMock()

        edb_resp = MagicMock()
        edb_resp.status_code = 200
        edb_resp.json.return_value = {"references": [f"https://example.com/ref/{i}" for i in range(250)]}
        edb_resp.raise_for_status = MagicMock()

        def mock_get(url, **kwargs):
            if "github.com" in url:
                return gh_resp
            return edb_resp

        with patch("cve.routes._exploit_client.get", new_callable=AsyncMock, side_effect=mock_get):
            r = client.get("/v1/exploit/CVE-2024-4101")
        assert r.status_code == 200
        shodan = r.json()["sources"]["shodan_refs"]
        assert shodan["count"] == 250, f"count must reflect honest upstream count (250), got {shodan['count']!r}"
        assert shodan["truncated"] is True, "truncated must be true when count > cap"
        assert len(shodan["results"]) == 200, f"results must be capped at 200, got {len(shodan['results'])}"

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    def test_shodan_refs_truncates_at_env_override(self, mock_cache_get, mock_cache_save):
        """SHODAN_REFS_LIMIT=20 + 50 refs upstream → count=50, truncated=true, len(results)=20."""
        gh_resp = MagicMock()
        gh_resp.json.return_value = []
        gh_resp.raise_for_status = MagicMock()

        edb_resp = MagicMock()
        edb_resp.status_code = 200
        edb_resp.json.return_value = {"references": [f"https://example.com/ref/{i}" for i in range(50)]}
        edb_resp.raise_for_status = MagicMock()

        def mock_get(url, **kwargs):
            if "github.com" in url:
                return gh_resp
            return edb_resp

        with patch("cve.routes.settings.shodan_refs_limit", 20):
            with patch("cve.routes._exploit_client.get", new_callable=AsyncMock, side_effect=mock_get):
                r = client.get("/v1/exploit/CVE-2024-4102")
        assert r.status_code == 200
        shodan = r.json()["sources"]["shodan_refs"]
        assert shodan["count"] == 50
        assert shodan["truncated"] is True
        assert len(shodan["results"]) == 20

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    def test_shodan_refs_under_cap(self, mock_cache_get, mock_cache_save):
        """5 refs + default cap=200 → count=5, truncated=false, len(results)=5."""
        gh_resp = MagicMock()
        gh_resp.json.return_value = []
        gh_resp.raise_for_status = MagicMock()

        edb_resp = MagicMock()
        edb_resp.status_code = 200
        edb_resp.json.return_value = {"references": [f"https://example.com/ref/{i}" for i in range(5)]}
        edb_resp.raise_for_status = MagicMock()

        def mock_get(url, **kwargs):
            if "github.com" in url:
                return gh_resp
            return edb_resp

        with patch("cve.routes._exploit_client.get", new_callable=AsyncMock, side_effect=mock_get):
            r = client.get("/v1/exploit/CVE-2024-4103")
        assert r.status_code == 200
        shodan = r.json()["sources"]["shodan_refs"]
        assert shodan["count"] == 5
        assert shodan["truncated"] is False
        assert len(shodan["results"]) == 5

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    def test_shodan_refs_404_returns_truncated_false(self, mock_cache_get, mock_cache_save):
        """Shodan 404 → count=0, truncated=false, results=[] (shape consistency)."""
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

        with patch("cve.routes._exploit_client.get", new_callable=AsyncMock, side_effect=mock_get):
            r = client.get("/v1/exploit/CVE-2024-4104")
        assert r.status_code == 200
        shodan = r.json()["sources"]["shodan_refs"]
        assert shodan["found"] is False
        assert shodan["count"] == 0
        assert shodan["truncated"] is False
        assert shodan["results"] == []

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    def test_shodan_refs_timeout_returns_truncated_false(self, mock_cache_get, mock_cache_save):
        """Shodan timeout → count=0, truncated=false, results=[] (shape consistency on error path)."""
        gh_resp = MagicMock()
        gh_resp.json.return_value = []
        gh_resp.raise_for_status = MagicMock()

        def mock_get(url, **kwargs):
            if "github.com" in url:
                return gh_resp
            raise httpx.ConnectTimeout("timeout")

        with patch("cve.routes._exploit_client.get", new_callable=AsyncMock, side_effect=mock_get):
            r = client.get("/v1/exploit/CVE-2024-4105")
        assert r.status_code == 200
        shodan = r.json()["sources"]["shodan_refs"]
        assert shodan["found"] is False
        assert shodan["count"] == 0
        assert shodan["truncated"] is False
        assert shodan["results"] == []

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    def test_shodan_refs_cap_1_min_boundary(self, mock_cache_get, mock_cache_save):
        """Field bounds min: cap=1, 2 refs upstream → count=2, truncated=true, len(results)=1."""
        gh_resp = MagicMock()
        gh_resp.json.return_value = []
        gh_resp.raise_for_status = MagicMock()

        edb_resp = MagicMock()
        edb_resp.status_code = 200
        edb_resp.json.return_value = {"references": ["https://example.com/ref/0", "https://example.com/ref/1"]}
        edb_resp.raise_for_status = MagicMock()

        def mock_get(url, **kwargs):
            if "github.com" in url:
                return gh_resp
            return edb_resp

        with patch("cve.routes.settings.shodan_refs_limit", 1):
            with patch("cve.routes._exploit_client.get", new_callable=AsyncMock, side_effect=mock_get):
                r = client.get("/v1/exploit/CVE-2024-4106")
        assert r.status_code == 200
        shodan = r.json()["sources"]["shodan_refs"]
        assert shodan["count"] == 2
        assert shodan["truncated"] is True
        assert len(shodan["results"]) == 1

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    def test_shodan_refs_cap_1000_max_boundary(self, mock_cache_get, mock_cache_save):
        """Field bounds max: cap=1000 + exactly 1000 refs upstream → count=1000, truncated=false (1000 > 1000 is false), len(results)=1000."""
        gh_resp = MagicMock()
        gh_resp.json.return_value = []
        gh_resp.raise_for_status = MagicMock()

        edb_resp = MagicMock()
        edb_resp.status_code = 200
        edb_resp.json.return_value = {"references": [f"https://example.com/ref/{i}" for i in range(1000)]}
        edb_resp.raise_for_status = MagicMock()

        def mock_get(url, **kwargs):
            if "github.com" in url:
                return gh_resp
            return edb_resp

        with patch("cve.routes.settings.shodan_refs_limit", 1000):
            with patch("cve.routes._exploit_client.get", new_callable=AsyncMock, side_effect=mock_get):
                r = client.get("/v1/exploit/CVE-2024-4107")
        assert r.status_code == 200
        shodan = r.json()["sources"]["shodan_refs"]
        assert shodan["count"] == 1000
        assert shodan["truncated"] is False
        assert len(shodan["results"]) == 1000

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    def test_shodan_refs_non_dict_response(self, mock_cache_get, mock_cache_save):
        """Defensive: malformed Shodan response (root is array not dict) → graceful degrade to count=0, truncated=false."""
        gh_resp = MagicMock()
        gh_resp.json.return_value = []
        gh_resp.raise_for_status = MagicMock()

        edb_resp = MagicMock()
        edb_resp.status_code = 200
        edb_resp.json.return_value = ["unexpected", "array", "root"]
        edb_resp.raise_for_status = MagicMock()

        def mock_get(url, **kwargs):
            if "github.com" in url:
                return gh_resp
            return edb_resp

        with patch("cve.routes._exploit_client.get", new_callable=AsyncMock, side_effect=mock_get):
            r = client.get("/v1/exploit/CVE-2024-4108")
        assert r.status_code == 200
        shodan = r.json()["sources"]["shodan_refs"]
        assert shodan["found"] is False
        assert shodan["count"] == 0
        assert shodan["truncated"] is False
        assert shodan["results"] == []


class TestBatch5KevExpansion:
    """Batch 5 — KEV expansion (KevInfo 2→11 fields), lifecycle (date_updated +
    date_removed soft-delete), NVD vulnerability_status + cve_tags. BREAKING
    SCHEMA migration #2."""

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    def test_kev_info_expanded_when_in_kev(self, mock_cache_get, mock_cache_save):
        """cve_lookup .kev returns 11 fields (not 2) when in_kev=1, populated from kev_details."""
        from db import upsert_cve, upsert_kev_details

        upsert_cve(
            {
                "cve_id": "CVE-2023-22518",
                "description": "Atlassian Confluence broken access control vulnerability.",
                "severity": "CRITICAL",
                "cvss_v3": 9.8,
                "in_kev": 1,
                "kev_date_added": "2023-11-03",
                "refs": [],
                "summary": "CRITICAL — broken access control. CVSS 9.8.",
            }
        )
        upsert_kev_details(
            "CVE-2023-22518",
            due_date="2023-11-24",
            required_action="Apply mitigations per vendor instructions.",
            known_ransomware_use=True,
            vendor_project="Atlassian",
            product="Confluence",
            vulnerability_name="Atlassian Confluence Broken Access Control",
            short_description="Atlassian Confluence broken access control vulnerability.",
            notes="https://confluence.atlassian.com/security/...",
            cwes=["CWE-863"],
            date_updated="2024-01-15",
        )
        r = client.get("/v1/cve/CVE-2023-22518")
        assert r.status_code == 200
        kev = r.json()["kev"]
        assert kev["in_kev"] is True
        assert kev["date_added"] == "2023-11-03"
        assert kev["due_date"] == "2023-11-24"
        assert kev["required_action"] == "Apply mitigations per vendor instructions."
        assert kev["known_ransomware_use"] is True
        assert kev["vendor_project"] == "Atlassian"
        assert kev["product"] == "Confluence"
        assert kev["vulnerability_name"] == "Atlassian Confluence Broken Access Control"
        assert kev["short_description"] == "Atlassian Confluence broken access control vulnerability."
        assert kev["notes"] == "https://confluence.atlassian.com/security/..."
        assert kev["cwes"] == ["CWE-863"]

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    def test_kev_info_minimal_when_not_in_kev(self, mock_cache_get, mock_cache_save):
        """When in_kev=0, kev nested object emits only in_kev=False (rest elided by exclude_none)."""
        from db import upsert_cve

        upsert_cve(
            {
                "cve_id": "CVE-2024-9999",
                "description": "Test non-KEV CVE.",
                "severity": "MEDIUM",
                "cvss_v3": 5.0,
                "in_kev": 0,
                "refs": [],
                "summary": "MEDIUM — test.",
            }
        )
        r = client.get("/v1/cve/CVE-2024-9999")
        assert r.status_code == 200
        kev = r.json()["kev"]
        assert kev.get("in_kev") is False
        assert "due_date" not in kev or kev.get("due_date") is None
        assert "required_action" not in kev or kev.get("required_action") is None

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    def test_vulnerability_status_in_response(self, mock_cache_get, mock_cache_save):
        """cve.vulnerability_status field exposed when populated from NVD."""
        from db import upsert_cve

        upsert_cve(
            {
                "cve_id": "CVE-2024-8888",
                "description": "Awaiting analysis CVE.",
                "severity": None,
                "cvss_v3": None,
                "in_kev": 0,
                "refs": [],
                "vulnerability_status": "Awaiting Analysis",
                "summary": "Awaiting analysis test.",
            }
        )
        r = client.get("/v1/cve/CVE-2024-8888")
        assert r.status_code == 200
        assert r.json()["vulnerability_status"] == "Awaiting Analysis"

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    def test_cve_tags_in_response(self, mock_cache_get, mock_cache_save):
        """cve.cve_tags field returned as list[str]."""
        from db import upsert_cve

        upsert_cve(
            {
                "cve_id": "CVE-2020-19909",
                "description": "Heap-based buffer overflow in foo.",
                "severity": "MEDIUM",
                "cvss_v3": 5.0,
                "in_kev": 0,
                "refs": [],
                "vulnerability_status": "Modified",
                "cve_tags": ["disputed"],
                "summary": "MEDIUM — heap overflow.",
            }
        )
        r = client.get("/v1/cve/CVE-2020-19909")
        assert r.status_code == 200
        assert r.json()["cve_tags"] == ["disputed"]

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    def test_disputed_cve_summary_prefix(self, mock_cache_get, mock_cache_save):
        """When cve_tags contains 'disputed', summary starts with [DISPUTED]."""
        from db import upsert_cve

        upsert_cve(
            {
                "cve_id": "CVE-2020-19910",
                "description": "Heap-based buffer overflow in foo. NOTE: many parties report this is a duplicate.",
                "severity": "MEDIUM",
                "cvss_v3": 5.0,
                "in_kev": 0,
                "refs": [],
                "vulnerability_status": "Modified",
                "cve_tags": ["disputed"],
                "summary": None,
            }
        )
        r = client.get("/v1/cve/CVE-2020-19910")
        assert r.status_code == 200
        summary = r.json()["summary"]
        assert summary.startswith("[DISPUTED]"), f"summary must start with [DISPUTED], got: {summary!r}"

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    def test_summary_first_sentence_preserves_note(self, mock_cache_get, mock_cache_save):
        """_generate_summary takes first sentence (not desc[:120]); preserves NOTE: cumlesi."""
        from db import upsert_cve

        upsert_cve(
            {
                "cve_id": "CVE-2020-19911",
                "description": "Buffer overflow in libfoo allows DoS. NOTE: reported as duplicate by many.",
                "severity": "LOW",
                "cvss_v3": 3.0,
                "in_kev": 0,
                "refs": [],
                "summary": None,
            }
        )
        r = client.get("/v1/cve/CVE-2020-19911")
        assert r.status_code == 200
        summary = r.json()["summary"]
        assert "Buffer overflow in libfoo allows DoS." in summary, f"first sentence must be intact, got: {summary!r}"

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    def test_rejected_status_completeness_partial(self, mock_cache_get, mock_cache_save):
        """vulnerability_status='Rejected' downgrades verdict.completeness to 'partial'."""
        from db import upsert_cve

        upsert_cve(
            {
                "cve_id": "CVE-2024-7777",
                "description": "Rejected CVE.",
                "severity": "HIGH",
                "cvss_v3": 7.0,
                "in_kev": 0,
                "refs": ["https://example.com/ref"],
                "vulnerability_status": "Rejected",
                "summary": "HIGH — rejected.",
            }
        )
        r = client.get("/v1/cve/CVE-2024-7777")
        assert r.status_code == 200
        verdict = r.json()["verdict"]
        assert verdict["completeness"] == "partial", (
            f"Rejected status must downgrade to partial, got: {verdict['completeness']!r}"
        )

    def test_kev_soft_delete_marks_removed(self):
        """sync_kev: pre-sync 2 in_kev=1, feed has 1 → removed CVE gets in_kev=0 + date_removed timestamp."""
        from db import get_cve, get_kev_details, upsert_cve, upsert_kev_details

        upsert_cve({"cve_id": "CVE-2024-RM01", "in_kev": 1, "kev_date_added": "2024-01-01", "refs": []})
        upsert_cve({"cve_id": "CVE-2024-RM02", "in_kev": 1, "kev_date_added": "2024-01-02", "refs": []})
        upsert_kev_details("CVE-2024-RM01", short_description="kept")
        upsert_kev_details("CVE-2024-RM02", short_description="will be removed")

        feed_resp = MagicMock()
        feed_resp.raise_for_status = MagicMock()
        feed_resp.json.return_value = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-RM01",
                    "dateAdded": "2024-01-01",
                    "shortDescription": "kept",
                    "knownRansomwareCampaignUse": "Unknown",
                    "cwes": [],
                }
            ]
        }
        from cve import sync as sync_mod

        with patch.object(sync_mod._client, "get", new_callable=AsyncMock, return_value=feed_resp):
            asyncio.run(sync_mod.sync_kev())

        rm02_kev = get_kev_details("CVE-2024-RM02")
        assert rm02_kev is None, "CVE-2024-RM02 should be soft-deleted (in_kev=0 → INNER JOIN excludes)"
        rm02_cve = get_cve("CVE-2024-RM02")
        assert rm02_cve is not None
        assert rm02_cve.get("in_kev") in (0, False), (
            f"in_kev must be 0 after soft-delete, got: {rm02_cve.get('in_kev')!r}"
        )

        from db import get_cve_db

        with get_cve_db() as con:
            row = con.execute("SELECT date_removed FROM kev_details WHERE cve_id=?", ("CVE-2024-RM02",)).fetchone()
            assert row is not None and row[0] is not None, "kev_details.date_removed must be populated for removed CVE"

    def test_kev_soft_delete_idempotent(self):
        """Re-running sync_kev on stable feed (already-removed CVE not in feed): date_removed unchanged."""
        from db import get_cve_db, upsert_cve, upsert_kev_details

        upsert_cve({"cve_id": "CVE-2024-RM03", "in_kev": 1, "kev_date_added": "2024-01-01", "refs": []})
        upsert_kev_details("CVE-2024-RM03", short_description="will be removed")

        feed_resp = MagicMock()
        feed_resp.raise_for_status = MagicMock()
        feed_resp.json.return_value = {"vulnerabilities": []}
        from cve import sync as sync_mod

        with patch.object(sync_mod._client, "get", new_callable=AsyncMock, return_value=feed_resp):
            asyncio.run(sync_mod.sync_kev())

        with get_cve_db() as con:
            row1 = con.execute("SELECT date_removed FROM kev_details WHERE cve_id=?", ("CVE-2024-RM03",)).fetchone()
        first_removed = row1[0]
        assert first_removed is not None

        with patch.object(sync_mod._client, "get", new_callable=AsyncMock, return_value=feed_resp):
            asyncio.run(sync_mod.sync_kev())

        with get_cve_db() as con:
            row2 = con.execute("SELECT date_removed FROM kev_details WHERE cve_id=?", ("CVE-2024-RM03",)).fetchone()
        assert row2[0] == first_removed, (
            f"idempotency: date_removed must not be re-stamped (was {first_removed!r}, now {row2[0]!r})"
        )

    def test_kev_date_updated_extracted_from_feed(self):
        """sync_kev passes feed dateUpdated → kev_details.date_updated column."""
        from db import get_cve_db, upsert_cve

        upsert_cve({"cve_id": "CVE-2024-DU01", "in_kev": 1, "kev_date_added": "2024-01-01", "refs": []})

        feed_resp = MagicMock()
        feed_resp.raise_for_status = MagicMock()
        feed_resp.json.return_value = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-DU01",
                    "dateAdded": "2024-01-01",
                    "dateUpdated": "2024-06-15",
                    "shortDescription": "test",
                    "knownRansomwareCampaignUse": "Unknown",
                    "cwes": [],
                }
            ]
        }
        from cve import sync as sync_mod

        with patch.object(sync_mod._client, "get", new_callable=AsyncMock, return_value=feed_resp):
            asyncio.run(sync_mod.sync_kev())

        with get_cve_db() as con:
            row = con.execute("SELECT date_updated FROM kev_details WHERE cve_id=?", ("CVE-2024-DU01",)).fetchone()
        assert row is not None and row[0] == "2024-06-15"

    def test_kev_detail_endpoint_exposes_new_fields(self):
        """kev_detail response: date_updated + date_removed (None when active) + updated_at all present."""
        from db import upsert_cve, upsert_kev_details

        upsert_cve({"cve_id": "CVE-2024-9001", "in_kev": 1, "kev_date_added": "2024-01-01", "refs": []})
        upsert_kev_details("CVE-2024-9001", short_description="active KEV", date_updated="2024-06-15")

        r = client.get("/v1/kev/CVE-2024-9001")
        assert r.status_code == 200
        body = r.json()
        assert body["date_updated"] == "2024-06-15"
        assert body.get("date_removed") is None
        assert body.get("updated_at") is not None

    def test_init_cve_db_migration_idempotent(self):
        """init_cve_db() called twice: no error; all 4 new columns exist."""
        from db import get_cve_db, init_cve_db

        init_cve_db()
        init_cve_db()
        with get_cve_db() as con:
            cve_cols = {row[1] for row in con.execute("PRAGMA table_info(cves)")}
            kev_cols = {row[1] for row in con.execute("PRAGMA table_info(kev_details)")}
        assert "vulnerability_status" in cve_cols
        assert "cve_tags" in cve_cols
        assert "date_updated" in kev_cols
        assert "date_removed" in kev_cols

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    def test_falsifiable_base_includes_new_fields(self, mock_cache_get, mock_cache_save):
        """When vulnerability_status + cve_tags populated, they appear in verdict.falsifiable_fields."""
        from db import upsert_cve

        upsert_cve(
            {
                "cve_id": "CVE-2024-9002",
                "description": "Test field falsifiability.",
                "severity": "HIGH",
                "cvss_v3": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cwe_id": "CWE-79",
                "cwes": ["CWE-79"],
                "in_kev": 0,
                "refs": ["https://example.com/x"],
                "vulnerability_status": "Analyzed",
                "cve_tags": ["unsupported-when-assigned"],
                "published": "2024-06-01T00:00:00Z",
                "summary": "test",
            }
        )
        r = client.get("/v1/cve/CVE-2024-9002")
        assert r.status_code == 200
        falsifiable = r.json()["verdict"]["falsifiable_fields"]
        assert "vulnerability_status" in falsifiable
        assert "cve_tags" in falsifiable

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    def test_lowercase_rejected_status_still_degrades(self, mock_cache_get, mock_cache_save):
        """Defense-in-depth: lowercase 'rejected' (feed quirk / proxy mutation) must still downgrade completeness."""
        from db import upsert_cve

        upsert_cve(
            {
                "cve_id": "CVE-2024-9003",
                "description": "Lowercase status feed quirk.",
                "severity": "HIGH",
                "cvss_v3": 7.0,
                "in_kev": 0,
                "refs": ["https://example.com/x"],
                "vulnerability_status": "rejected",
                "summary": "HIGH — lowercase status.",
            }
        )
        r = client.get("/v1/cve/CVE-2024-9003")
        assert r.status_code == 200
        verdict = r.json()["verdict"]
        assert verdict["completeness"] == "partial", (
            f"lowercase 'rejected' must downgrade to partial, got: {verdict['completeness']!r}"
        )


class TestBatch6BackendIngestion:
    """Batch 6A — NVD references[].tags adoption + total_references honesty.
    DB migration #3 v1.29.x adds refs_with_tags (JSON) + total_references_upstream (INT).
    4 parsers (NVD/MITRE/GHSA/OSV) emit structured [{url, tags, source}] refs.
    Response gains total_references_unique field. API contract unchanged (6B opts in)."""

    def test_nvd_parser_extracts_refs_with_tags_and_source(self):
        """NVD parser returns refs_with_tags=[{url, tags, source}] for each unique reference."""
        from cve.sync import _parse_nvd_cve

        item = {
            "cve": {
                "id": "CVE-2099-1001",
                "descriptions": [{"lang": "en", "value": "Test"}],
                "references": [
                    {"url": "https://example.com/a", "tags": ["Patch", "Vendor Advisory"], "source": "cna@example.com"},
                    {"url": "https://example.com/b", "tags": ["Mailing List"], "source": "ml@example.com"},
                ],
                "metrics": {},
                "weaknesses": [],
                "configurations": [],
                "published": "2024-01-01T00:00:00",
                "lastModified": "2024-01-02T00:00:00",
            }
        }
        out = _parse_nvd_cve(item)
        assert "refs_with_tags" in out
        assert out["refs_with_tags"] == [
            {"url": "https://example.com/a", "tags": ["Patch", "Vendor Advisory"], "source": "cna@example.com"},
            {"url": "https://example.com/b", "tags": ["Mailing List"], "source": "ml@example.com"},
        ]

    def test_nvd_parser_total_references_upstream_raw_count(self):
        """total_references_upstream = raw count BEFORE dedup (source-mirror duplicates included)."""
        from cve.sync import _parse_nvd_cve

        item = {
            "cve": {
                "id": "CVE-2099-1002",
                "descriptions": [{"lang": "en", "value": "Test"}],
                "references": [
                    {"url": "https://example.com/x", "source": "src1", "tags": []},
                    {"url": "https://example.com/x", "source": "src2", "tags": ["Patch"]},
                    {"url": "https://example.com/y", "source": "src1", "tags": []},
                ],
                "metrics": {},
                "weaknesses": [],
                "configurations": [],
                "published": "2024-01-01T00:00:00",
                "lastModified": "2024-01-02T00:00:00",
            }
        }
        out = _parse_nvd_cve(item)
        assert out["total_references_upstream"] == 3
        assert len(out["refs_with_tags"]) == 2

    def test_nvd_parser_dedup_by_url_first_wins(self):
        """Same URL twice: first occurrence wins (tags/source from first entry, not merged)."""
        from cve.sync import _parse_nvd_cve

        item = {
            "cve": {
                "id": "CVE-2099-1003",
                "descriptions": [{"lang": "en", "value": "Test"}],
                "references": [
                    {"url": "https://dup.example.com/", "tags": ["Patch"], "source": "first"},
                    {"url": "https://dup.example.com/", "tags": ["Exploit"], "source": "second"},
                ],
                "metrics": {},
                "weaknesses": [],
                "configurations": [],
                "published": "2024-01-01T00:00:00",
                "lastModified": "2024-01-02T00:00:00",
            }
        }
        out = _parse_nvd_cve(item)
        assert len(out["refs_with_tags"]) == 1
        assert out["refs_with_tags"][0]["tags"] == ["Patch"]
        assert out["refs_with_tags"][0]["source"] == "first"

    def test_nvd_parser_handles_missing_tags_field(self):
        """NVD ref without `tags` field -> tags=[], source preserved."""
        from cve.sync import _parse_nvd_cve

        item = {
            "cve": {
                "id": "CVE-2099-1004",
                "descriptions": [{"lang": "en", "value": "Test"}],
                "references": [
                    {"url": "https://no-tags.example.com/", "source": "anon@example.com"},
                ],
                "metrics": {},
                "weaknesses": [],
                "configurations": [],
                "published": "2024-01-01T00:00:00",
                "lastModified": "2024-01-02T00:00:00",
            }
        }
        out = _parse_nvd_cve(item)
        assert out["refs_with_tags"] == [
            {"url": "https://no-tags.example.com/", "tags": [], "source": "anon@example.com"},
        ]

    def test_mitre_parser_source_mitre_tags_empty(self):
        """MITRE parser: source='mitre', tags=[] (MITRE v5.1 has no tags field)."""
        from cve.sync import _parse_mitre_cve

        item = {
            "cveMetadata": {"cveId": "CVE-2099-2001", "datePublished": "2024-01-01", "dateUpdated": "2024-01-02"},
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "MITRE test."}],
                    "references": [
                        {"url": "https://mitre.example.com/a"},
                        {"url": "https://mitre.example.com/b"},
                    ],
                    "metrics": [],
                    "problemTypes": [],
                    "affected": [],
                }
            },
        }
        out = _parse_mitre_cve(item)
        assert out["refs_with_tags"] == [
            {"url": "https://mitre.example.com/a", "tags": [], "source": "mitre"},
            {"url": "https://mitre.example.com/b", "tags": [], "source": "mitre"},
        ]
        assert out["total_references_upstream"] == 2

    def test_ghsa_parser_source_ghsa_tags_empty(self):
        """GHSA parser: source='ghsa', tags=[] (GHSA refs are bare URL strings)."""
        from cve.sync import _parse_ghsa_advisory

        item = {
            "cve_id": "CVE-2099-3001",
            "summary": "GHSA test.",
            "references": [
                "https://ghsa.example.com/a",
                "https://ghsa.example.com/b",
            ],
            "published_at": "2024-01-01",
            "updated_at": "2024-01-02",
        }
        out = _parse_ghsa_advisory(item)
        assert out["refs_with_tags"] == [
            {"url": "https://ghsa.example.com/a", "tags": [], "source": "ghsa"},
            {"url": "https://ghsa.example.com/b", "tags": [], "source": "ghsa"},
        ]
        assert out["total_references_upstream"] == 2

    def test_osv_parser_source_osv_tags_empty(self):
        """OSV parser: source='osv', tags=[] (OSV refs are dicts with url+type, no tags)."""
        from cve.sync import _parse_osv_vulnerability

        vuln = {
            "id": "OSV-1",
            "aliases": ["CVE-2099-4001"],
            "summary": "OSV test.",
            "details": "OSV detailed text.",
            "published": "2024-01-01",
            "modified": "2024-01-02",
            "severity": [],
            "references": [
                {"type": "ADVISORY", "url": "https://osv.example.com/a"},
                {"type": "WEB", "url": "https://osv.example.com/b"},
            ],
            "affected": [],
            "database_specific": {},
        }
        out = _parse_osv_vulnerability(vuln)
        assert out["refs_with_tags"] == [
            {"url": "https://osv.example.com/a", "tags": [], "source": "osv"},
            {"url": "https://osv.example.com/b", "tags": [], "source": "osv"},
        ]
        assert out["total_references_upstream"] == 2

    def test_db_migration_adds_refs_with_tags_column_idempotent(self):
        """init_cve_db() adds refs_with_tags + total_references_upstream columns; re-run is no-op."""
        from db import get_cve_db, init_cve_db

        init_cve_db()
        init_cve_db()
        with get_cve_db() as con:
            cols = {row[1] for row in con.execute("PRAGMA table_info(cves)")}
        assert "refs_with_tags" in cols
        assert "total_references_upstream" in cols

    def test_upsert_cve_round_trip_refs_with_tags(self):
        """upsert_cve writes refs_with_tags as JSON; get_cve parses back to list[dict]."""
        from db import get_cve, upsert_cve

        upsert_cve(
            {
                "cve_id": "CVE-2099-5001",
                "description": "Round-trip test.",
                "severity": "MEDIUM",
                "cvss_v3": 5.0,
                "in_kev": 0,
                "refs": ["https://rt.example.com/a"],
                "refs_with_tags": [
                    {"url": "https://rt.example.com/a", "tags": ["Patch"], "source": "test"},
                ],
                "total_references_upstream": 1,
                "summary": "MEDIUM — round trip.",
            }
        )
        out = get_cve("CVE-2099-5001")
        assert out is not None
        assert out["refs_with_tags"] == [
            {"url": "https://rt.example.com/a", "tags": ["Patch"], "source": "test"},
        ]
        assert out["total_references_upstream"] == 1

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    def test_total_references_unique_field_in_response(self, mock_cache_get, mock_cache_save):
        """GET /v1/cve/{id} response includes total_references_unique = len(refs_with_tags) when available."""
        from db import upsert_cve

        upsert_cve(
            {
                "cve_id": "CVE-2099-6001",
                "description": "Response field test.",
                "severity": "HIGH",
                "cvss_v3": 7.5,
                "in_kev": 0,
                "refs": ["https://r.example.com/a", "https://r.example.com/b"],
                "refs_with_tags": [
                    {"url": "https://r.example.com/a", "tags": ["Patch"], "source": "nvd"},
                    {"url": "https://r.example.com/b", "tags": [], "source": "nvd"},
                ],
                "total_references_upstream": 2,
                "summary": "HIGH — total_references_unique check.",
            }
        )
        r = client.get("/v1/cve/CVE-2099-6001")
        assert r.status_code == 200
        body = r.json()
        assert body.get("total_references_unique") == 2

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    def test_total_references_unique_zero_for_empty_refs_with_tags(self, mock_cache_get, mock_cache_save):
        """Fold-in: empty refs_with_tags=[] returns 0, NOT None.
        None reserved for legacy rows (refs_with_tags column NULL); zero distinct from never-synced."""
        from db import upsert_cve

        upsert_cve(
            {
                "cve_id": "CVE-2099-6002",
                "description": "Empty refs edge case.",
                "severity": "LOW",
                "cvss_v3": 3.0,
                "in_kev": 0,
                "refs": [],
                "refs_with_tags": [],
                "total_references_upstream": 0,
                "summary": "LOW — empty refs synced.",
            }
        )
        r = client.get("/v1/cve/CVE-2099-6002")
        assert r.status_code == 200
        body = r.json()
        assert body.get("total_references_unique") == 0, (
            f"empty refs_with_tags=[] must return 0 (synced, no upstream refs), got: {body.get('total_references_unique')!r}"
        )

    def test_nvd_parser_non_list_references_safe(self):
        """Fold-in (CWE-704): malformed feed sending references=<non-list> must not corrupt total_references_upstream."""
        from cve.sync import _parse_nvd_cve

        item = {
            "cve": {
                "id": "CVE-2099-1099",
                "descriptions": [{"lang": "en", "value": "Malformed feed test"}],
                "references": "not-a-list",
                "metrics": {},
                "weaknesses": [],
                "configurations": [],
                "published": "2024-01-01T00:00:00",
                "lastModified": "2024-01-02T00:00:00",
            }
        }
        out = _parse_nvd_cve(item)
        assert out["refs_with_tags"] == []
        assert out["total_references_upstream"] == 0

    def test_mitre_parser_non_list_references_safe(self):
        """Fold-in (CWE-704): MITRE parser handles non-list references defensively."""
        from cve.sync import _parse_mitre_cve

        item = {
            "cveMetadata": {"cveId": "CVE-2099-2099", "datePublished": "2024-01-01", "dateUpdated": "2024-01-02"},
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "Malformed."}],
                    "references": {"unexpected": "dict"},
                    "metrics": [],
                    "problemTypes": [],
                    "affected": [],
                }
            },
        }
        out = _parse_mitre_cve(item)
        assert out["refs_with_tags"] == []
        assert out["total_references_upstream"] == 0

    def test_ghsa_parser_non_list_references_safe(self):
        """Fold-in (CWE-704): GHSA parser handles non-list references defensively."""
        from cve.sync import _parse_ghsa_advisory

        item = {
            "cve_id": "CVE-2099-3099",
            "summary": "Malformed.",
            "references": "single-string-not-list",
            "published_at": "2024-01-01",
            "updated_at": "2024-01-02",
        }
        out = _parse_ghsa_advisory(item)
        assert out["refs_with_tags"] == []
        assert out["total_references_upstream"] == 0


class TestBatch6APISurface:
    """Batch 6B — API surface: opt-in include_reference_tags flag activates 6A's refs_with_tags
    DB column via new references_full response field. Tag-first patch detection ({Patch,
    Vendor Advisory} whitelist) with Batch 1 regex fallback for legacy cache rows."""

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    def test_cve_lookup_default_returns_references_full_none(self, mock_cache_get, mock_cache_save):
        """Backward compat: GET without flag → references list[str], references_full omitted (None default)."""
        from db import upsert_cve

        upsert_cve(
            {
                "cve_id": "CVE-2099-7001",
                "description": "Default response shape test.",
                "severity": "HIGH",
                "cvss_v3": 7.0,
                "in_kev": 0,
                "refs": ["https://r.example.com/a"],
                "refs_with_tags": [{"url": "https://r.example.com/a", "tags": ["Patch"], "source": "nvd"}],
                "total_references_upstream": 1,
                "summary": "HIGH — backward compat.",
            }
        )
        r = client.get("/v1/cve/CVE-2099-7001")
        assert r.status_code == 200
        body = r.json()
        assert body["references"] == ["https://r.example.com/a"]
        assert body.get("references_full") is None, (
            f"references_full must be None when flag not set, got: {body.get('references_full')!r}"
        )

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    def test_cve_lookup_include_reference_tags_returns_objects(self, mock_cache_get, mock_cache_save):
        """Opt-in: ?include_reference_tags=true → references_full populated with structured objects."""
        from db import upsert_cve

        upsert_cve(
            {
                "cve_id": "CVE-2099-7002",
                "description": "Opt-in shape test.",
                "severity": "HIGH",
                "cvss_v3": 7.5,
                "in_kev": 0,
                "refs": ["https://r.example.com/a", "https://r.example.com/b"],
                "refs_with_tags": [
                    {
                        "url": "https://r.example.com/a",
                        "tags": ["Patch", "Vendor Advisory"],
                        "source": "cna@example.com",
                    },
                    {"url": "https://r.example.com/b", "tags": ["Mailing List"], "source": "ml@example.com"},
                ],
                "total_references_upstream": 2,
                "summary": "HIGH — opt-in flag.",
            }
        )
        r = client.get("/v1/cve/CVE-2099-7002?include_reference_tags=true")
        assert r.status_code == 200
        body = r.json()
        assert body["references"] == ["https://r.example.com/a", "https://r.example.com/b"]
        assert body["references_full"] == [
            {"url": "https://r.example.com/a", "tags": ["Patch", "Vendor Advisory"], "source": "cna@example.com"},
            {"url": "https://r.example.com/b", "tags": ["Mailing List"], "source": "ml@example.com"},
        ]

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    def test_reference_item_shape_keys(self, mock_cache_get, mock_cache_save):
        """ReferenceItem schema: each entry has {url, tags, source} keys when source non-None.
        Note: response_model_exclude_none=True drops source key when None (consistent with
        total_references_unique pattern); test uses non-None source to verify full shape."""
        from db import upsert_cve

        upsert_cve(
            {
                "cve_id": "CVE-2099-7003",
                "description": "Shape test.",
                "severity": "MEDIUM",
                "cvss_v3": 5.0,
                "in_kev": 0,
                "refs": ["https://s.example.com/x"],
                "refs_with_tags": [{"url": "https://s.example.com/x", "tags": [], "source": "nvd"}],
                "total_references_upstream": 1,
                "summary": "MEDIUM — shape.",
            }
        )
        r = client.get("/v1/cve/CVE-2099-7003?include_reference_tags=true")
        assert r.status_code == 200
        body = r.json()
        ref = body["references_full"][0]
        assert set(ref.keys()) == {"url", "tags", "source"}
        assert ref["tags"] == []
        assert ref["source"] == "nvd"

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    def test_include_reference_tags_orthogonal_to_full_references(self, mock_cache_get, mock_cache_save):
        """Combination: ?include_full_references=true&include_reference_tags=true returns ALL refs as objects (no truncation)."""
        from db import upsert_cve

        big_refs = [{"url": f"https://o.example.com/{i}", "tags": [], "source": "nvd"} for i in range(15)]
        upsert_cve(
            {
                "cve_id": "CVE-2099-7004",
                "description": "Truncation orthogonality test.",
                "severity": "HIGH",
                "cvss_v3": 7.0,
                "in_kev": 0,
                "refs": [r["url"] for r in big_refs],
                "refs_with_tags": big_refs,
                "total_references_upstream": 15,
                "summary": "HIGH — orthogonal flags.",
            }
        )
        r = client.get("/v1/cve/CVE-2099-7004?include_full_references=true&include_reference_tags=true")
        assert r.status_code == 200
        body = r.json()
        assert len(body["references_full"]) == 15
        assert len(body["references"]) == 15

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    def test_patch_detection_tag_first_patch(self, mock_cache_get, mock_cache_save):
        """Tag-first: NVD ref with tags=['Patch'] yields patch_url even when URL doesn't match Batch 1 regex."""
        from db import upsert_cve

        non_regex_url = "https://obscure-vendor.example.com/security/2024/advisory.html"
        upsert_cve(
            {
                "cve_id": "CVE-2099-7005",
                "description": "Tag-first patch detection.",
                "severity": "HIGH",
                "cvss_v3": 7.0,
                "in_kev": 0,
                "refs": [non_regex_url],
                "refs_with_tags": [{"url": non_regex_url, "tags": ["Patch"], "source": "nvd"}],
                "total_references_upstream": 1,
                "summary": "HIGH — tag-first.",
            }
        )
        r = client.get("/v1/cve/CVE-2099-7005")
        assert r.status_code == 200
        body = r.json()
        assert body["patch_available"] is True
        assert body["patch_url"] == non_regex_url

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    def test_patch_detection_tag_first_vendor_advisory(self, mock_cache_get, mock_cache_save):
        """Tag-first: Vendor Advisory tag also yields patch_url."""
        from db import upsert_cve

        url = "https://vendor.example.com/sa-2024-001"
        upsert_cve(
            {
                "cve_id": "CVE-2099-7006",
                "description": "Vendor Advisory tag-first.",
                "severity": "HIGH",
                "cvss_v3": 7.0,
                "in_kev": 0,
                "refs": [url],
                "refs_with_tags": [{"url": url, "tags": ["Vendor Advisory"], "source": "nvd"}],
                "total_references_upstream": 1,
                "summary": "HIGH — vendor advisory.",
            }
        )
        r = client.get("/v1/cve/CVE-2099-7006")
        assert r.status_code == 200
        body = r.json()
        assert body["patch_available"] is True
        assert body["patch_url"] == url

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    def test_patch_detection_tag_case_insensitive(self, mock_cache_get, mock_cache_save):
        """Tag-first: lowercase 'patch' tag (feed quirk) still matches whitelist."""
        from db import upsert_cve

        url = "https://lower.example.com/fix"
        upsert_cve(
            {
                "cve_id": "CVE-2099-7007",
                "description": "Case-insensitive tag.",
                "severity": "HIGH",
                "cvss_v3": 7.0,
                "in_kev": 0,
                "refs": [url],
                "refs_with_tags": [{"url": url, "tags": ["patch"], "source": "nvd"}],
                "total_references_upstream": 1,
                "summary": "HIGH — case-insensitive.",
            }
        )
        r = client.get("/v1/cve/CVE-2099-7007")
        assert r.status_code == 200
        body = r.json()
        assert body["patch_available"] is True
        assert body["patch_url"] == url

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    def test_patch_detection_regex_fallback_legacy_null(self, mock_cache_get, mock_cache_save):
        """Legacy cache row (refs_with_tags=None): regex fallback still detects kernel.org/MS/Apple URLs."""
        from db import upsert_cve

        kernel_url = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=abcd1234"
        upsert_cve(
            {
                "cve_id": "CVE-2099-7008",
                "description": "Regex fallback test.",
                "severity": "HIGH",
                "cvss_v3": 7.0,
                "in_kev": 0,
                "refs": [kernel_url],
                "summary": "HIGH — regex fallback.",
            }
        )
        r = client.get("/v1/cve/CVE-2099-7008")
        assert r.status_code == 200
        body = r.json()
        assert body["patch_available"] is True
        assert body["patch_url"] == kernel_url

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    def test_bulk_cve_lookup_include_reference_tags(self, mock_cache_get, mock_cache_save):
        """bulk_cve_lookup body field include_reference_tags propagates to per-item references_full."""
        from db import upsert_cve

        url = "https://b.example.com/x"
        upsert_cve(
            {
                "cve_id": "CVE-2099-7009",
                "description": "Bulk opt-in.",
                "severity": "HIGH",
                "cvss_v3": 7.0,
                "in_kev": 0,
                "refs": [url],
                "refs_with_tags": [{"url": url, "tags": ["Patch"], "source": "nvd"}],
                "total_references_upstream": 1,
                "summary": "HIGH — bulk.",
            }
        )
        r = client.post(
            "/v1/cves/bulk",
            json={"cve_ids": ["CVE-2099-7009"], "include_reference_tags": True},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["successful"] == 1
        cve_payload = body["results"][0]["cve"]
        assert cve_payload["references_full"] == [
            {"url": url, "tags": ["Patch"], "source": "nvd"},
        ]

    def test_cache_key_versioning_separates_flag_variants(self):
        """Cache key includes int(include_reference_tags) so flag=False and flag=True payloads stay distinct.
        Verifies asave_cached_domain receives 2 separate cache keys for the same CVE."""
        from db import upsert_cve

        url = "https://c.example.com/x"
        upsert_cve(
            {
                "cve_id": "CVE-2099-7010",
                "description": "Cache key versioning.",
                "severity": "HIGH",
                "cvss_v3": 7.0,
                "in_kev": 0,
                "refs": [url],
                "refs_with_tags": [{"url": url, "tags": ["Patch"], "source": "nvd"}],
                "total_references_upstream": 1,
                "summary": "HIGH — cache key.",
            }
        )
        with (
            patch("cve.routes.asave_cached_domain", new_callable=AsyncMock) as mock_save,
            patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None),
        ):
            r1 = client.get("/v1/cve/CVE-2099-7010")
            r2 = client.get("/v1/cve/CVE-2099-7010?include_reference_tags=true")
        assert r1.status_code == 200
        assert r2.status_code == 200
        cache_keys = {call.args[0] for call in mock_save.call_args_list}
        assert len(cache_keys) == 2, f"expected 2 distinct cache keys, got: {cache_keys!r}"
        # Both keys begin with cve_lookup:CVE-2099-7010 but differ in the flag bitmask suffix.
        assert all(k.startswith("cve_lookup:CVE-2099-7010:") for k in cache_keys)

    @patch("cve.routes.asave_cached_domain", new_callable=AsyncMock)
    @patch("cve.routes.aget_cached_domain", new_callable=AsyncMock, return_value=None)
    def test_patch_detection_tag_first_blocked_by_redirect_pattern(self, mock_cache_get, mock_cache_save):
        """Fold-in (CWE-601 regression guard): tag-first path must apply _REDIRECT_BLOCKLIST.
        A Patch-tagged URL containing a redirect pattern (?to=, /redirect) must NOT be emitted
        as patch_url — falls through to regex fallback (which also rejects). Locks in symmetry
        with regex path so future refactors of _extract_patch_url cannot silently drop the
        blocklist guard on the tag-first branch."""
        from db import upsert_cve

        redirect_url = "https://vendor.example.com/redirect?to=attacker.example.com/evil"
        upsert_cve(
            {
                "cve_id": "CVE-2099-7011",
                "description": "Open-redirect rejection on tag-first path.",
                "severity": "HIGH",
                "cvss_v3": 7.0,
                "in_kev": 0,
                "refs": [redirect_url],
                "refs_with_tags": [{"url": redirect_url, "tags": ["Patch"], "source": "nvd"}],
                "total_references_upstream": 1,
                "summary": "HIGH — redirect-blocklist rejection.",
            }
        )
        r = client.get("/v1/cve/CVE-2099-7011")
        assert r.status_code == 200
        body = r.json()
        assert body["patch_available"] is False, (
            f"tag-tagged URL with redirect pattern must be rejected by blocklist, "
            f"got patch_available={body['patch_available']!r} patch_url={body.get('patch_url')!r}"
        )
        assert body.get("patch_url") is None


class TestBatch7CvssV2AndSeveritySources:
    """Batch 7: CVSSv2 storage + multi-source severity merge + exploitdb_meta singleton.

    Bugs covered:
      BUG-SYNC-4: NVD CVSSv2 baseScore + vectorString extraction (was severity-only).
      BUG-SCH-3:  cves.cvss_v2 / cvss_v2_vector columns + severity_sources JSON column.
      BUG-SEV-2:  multi-source severity merge (consensus + cross-version disagreement).
      BUG-15:     exploitdb_meta singleton table for per-feed sync timestamp."""

    def test_nvd_parser_extracts_cvss_v2_base_score_and_vector(self):
        from cve.sync import _parse_nvd_cve

        item = {
            "cve": {
                "id": "CVE-2008-0166",
                "descriptions": [{"lang": "en", "value": "Debian OpenSSL PRNG."}],
                "metrics": {
                    "cvssMetricV2": [
                        {
                            "cvssData": {
                                "baseScore": 10.0,
                                "vectorString": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                                "baseSeverity": "HIGH",
                            }
                        }
                    ]
                },
            }
        }
        out = _parse_nvd_cve(item)
        assert out["cvss_v2"] == 10.0, f"expected cvss_v2=10.0, got {out.get('cvss_v2')!r}"
        assert out["cvss_v2_vector"] == "AV:N/AC:L/Au:N/C:C/I:C/A:C"

    def test_nvd_parser_severity_sources_includes_v2_when_only_v2(self):
        from cve.sync import _parse_nvd_cve

        item = {
            "cve": {
                "id": "CVE-2009-3555",
                "descriptions": [{"lang": "en", "value": "TLS reneg."}],
                "metrics": {
                    "cvssMetricV2": [
                        {
                            "cvssData": {
                                "baseScore": 5.8,
                                "vectorString": "AV:N/AC:M/Au:N/C:P/I:P/A:N",
                                "baseSeverity": "MEDIUM",
                            }
                        }
                    ]
                },
            }
        }
        out = _parse_nvd_cve(item)
        assert out["cvss_v3"] is None
        assert out["cvss_v2"] == 5.8
        assert out["severity"] == "MEDIUM", f"v2 baseSeverity must populate severity, got {out.get('severity')!r}"
        sev_sources = out.get("severity_sources") or []
        assert len(sev_sources) == 1, f"expected 1 NVD entry, got {sev_sources!r}"
        e = sev_sources[0]
        assert e["source"] == "nvd"
        assert e["severity"] == "MEDIUM"
        assert e["cvss_v3"] is None
        assert e["cvss_v2"] == 5.8

    def test_nvd_parser_severity_sources_includes_v3_when_present(self):
        from cve.sync import _parse_nvd_cve

        item = {
            "cve": {
                "id": "CVE-2021-44228",
                "descriptions": [{"lang": "en", "value": "Log4Shell."}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 10.0,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                "baseSeverity": "CRITICAL",
                            }
                        }
                    ]
                },
            }
        }
        out = _parse_nvd_cve(item)
        sev_sources = out.get("severity_sources") or []
        assert len(sev_sources) == 1
        assert sev_sources[0]["source"] == "nvd"
        assert sev_sources[0]["severity"] == "CRITICAL"
        assert sev_sources[0]["cvss_v3"] == 10.0

    def test_ghsa_parser_extracts_severity_into_severity_sources(self):
        from cve.sync import _parse_ghsa_advisory

        adv = {
            "cve_id": "CVE-2023-38545",
            "summary": "curl SOCKS5.",
            "severity": "high",
            "published_at": "2023-10-11T00:00:00Z",
            "updated_at": "2023-10-11T00:00:00Z",
            "references": [],
        }
        out = _parse_ghsa_advisory(adv)
        sev_sources = out.get("severity_sources") or []
        assert len(sev_sources) == 1, f"expected 1 GHSA entry, got {sev_sources!r}"
        assert sev_sources[0]["source"] == "ghsa"
        assert sev_sources[0]["severity"] == "HIGH"

    def test_mitre_parser_emits_severity_sources(self):
        from cve.sync import _parse_mitre_cve

        item = {
            "cveMetadata": {"cveId": "CVE-2024-99999", "state": "PUBLISHED"},
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "MITRE test."}],
                    "metrics": [
                        {
                            "cvssV3_1": {
                                "baseScore": 7.5,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                "baseSeverity": "HIGH",
                            }
                        }
                    ],
                }
            },
        }
        out = _parse_mitre_cve(item)
        sev_sources = out.get("severity_sources") or []
        assert len(sev_sources) == 1
        assert sev_sources[0]["source"] == "mitre"
        assert sev_sources[0]["severity"] == "HIGH"
        assert sev_sources[0]["cvss_v3"] == 7.5

    def test_osv_parser_emits_severity_sources(self):
        from cve.sync import _parse_osv_vulnerability

        vuln = {
            "id": "GHSA-xxxx-xxxx-xxxx",
            "aliases": ["CVE-2024-88888"],
            "summary": "OSV test.",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        }
        out = _parse_osv_vulnerability(vuln)
        sev_sources = out.get("severity_sources") or []
        assert len(sev_sources) == 1
        assert sev_sources[0]["source"] == "osv"
        assert sev_sources[0]["cvss_v3"] is not None

    def test_db_migration_adds_cvss_v2_and_severity_sources_columns(self):
        from db import get_cve_db, init_cve_db

        init_cve_db()
        with get_cve_db() as con:
            cols = {row[1] for row in con.execute("PRAGMA table_info(cves)")}
        assert "cvss_v2" in cols, f"cves.cvss_v2 missing; cols={sorted(cols)}"
        assert "cvss_v2_vector" in cols
        assert "severity_sources" in cols

    def test_db_migration_creates_exploitdb_meta_singleton_table(self):
        from db import get_cve_db, init_cve_db

        init_cve_db()
        with get_cve_db() as con:
            tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert "exploitdb_meta" in tables, f"exploitdb_meta table missing; tables={sorted(tables)}"
        with get_cve_db() as con:
            cols = {row[1] for row in con.execute("PRAGMA table_info(exploitdb_meta)")}
        assert "synced_at" in cols

    def test_db_migration_idempotent(self):
        from db import init_cve_db

        init_cve_db()
        init_cve_db()  # second call must not raise

    def test_upsert_cve_persists_cvss_v2_and_severity_sources(self):
        from db import get_cve, upsert_cve

        upsert_cve(
            {
                "cve_id": "CVE-2099-7100",
                "description": "Roundtrip test.",
                "severity": "HIGH",
                "cvss_v3": 7.5,
                "cvss_v2": 6.8,
                "cvss_v2_vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
                "severity_sources": [
                    {"source": "nvd", "severity": "HIGH", "cvss_v3": 7.5, "cvss_v2": 6.8},
                ],
                "in_kev": 0,
                "refs": [],
                "summary": "test",
            }
        )
        row = get_cve("CVE-2099-7100")
        assert row is not None
        assert row["cvss_v2"] == 6.8
        assert row["cvss_v2_vector"] == "AV:N/AC:M/Au:N/C:P/I:P/A:P"
        assert row["severity_sources"] == [
            {"source": "nvd", "severity": "HIGH", "cvss_v3": 7.5, "cvss_v2": 6.8},
        ]

    def test_exploitdb_meta_singleton_round_trip(self):
        from db import get_exploitdb_synced_at, set_exploitdb_synced_at

        set_exploitdb_synced_at("2026-05-08T12:00:00+00:00")
        assert get_exploitdb_synced_at() == "2026-05-08T12:00:00+00:00"
        # Singleton — second set replaces, doesn't insert
        set_exploitdb_synced_at("2026-05-08T13:00:00+00:00")
        assert get_exploitdb_synced_at() == "2026-05-08T13:00:00+00:00"

    def test_cve_lookup_returns_cvss_v2_in_default_response(self):
        from db import upsert_cve

        upsert_cve(
            {
                "cve_id": "CVE-2099-7101",
                "description": "Default response cvss_v2.",
                "severity": "MEDIUM",
                "cvss_v2": 5.8,
                "cvss_v2_vector": "AV:N/AC:M/Au:N/C:P/I:P/A:N",
                "in_kev": 0,
                "refs": [],
                "summary": "test",
            }
        )
        r = client.get("/v1/cve/CVE-2099-7101")
        assert r.status_code == 200
        body = r.json()
        assert body["cvss_v2"] == 5.8
        assert body["cvss_v2_vector"] == "AV:N/AC:M/Au:N/C:P/I:P/A:N"

    def test_cve_lookup_default_omits_severity_breakdown_fields(self):
        from db import upsert_cve

        upsert_cve(
            {
                "cve_id": "CVE-2099-7102",
                "description": "Default omits breakdown.",
                "severity": "HIGH",
                "cvss_v3": 7.5,
                "severity_sources": [
                    {"source": "nvd", "severity": "HIGH", "cvss_v3": 7.5, "cvss_v2": None},
                ],
                "in_kev": 0,
                "refs": [],
                "summary": "test",
            }
        )
        r = client.get("/v1/cve/CVE-2099-7102")
        assert r.status_code == 200
        body = r.json()
        assert "severity_sources" not in body, "severity_sources must be omitted without flag"
        assert "severity_consensus" not in body
        assert "severity_disagreement" not in body

    def test_cve_lookup_with_severity_breakdown_flag_emits_sources_and_consensus(self):
        from db import upsert_cve

        upsert_cve(
            {
                "cve_id": "CVE-2099-7103",
                "description": "Multi-source consensus.",
                "severity": "CRITICAL",
                "cvss_v3": 9.8,
                "severity_sources": [
                    {"source": "nvd", "severity": "CRITICAL", "cvss_v3": 9.8, "cvss_v2": None},
                    {"source": "ghsa", "severity": "HIGH", "cvss_v3": 7.5, "cvss_v2": None},
                ],
                "in_kev": 0,
                "refs": [],
                "summary": "test",
            }
        )
        r = client.get("/v1/cve/CVE-2099-7103?include_severity_breakdown=true")
        assert r.status_code == 200
        body = r.json()
        assert body["severity_sources"] == [
            {"source": "nvd", "severity": "CRITICAL", "cvss_v3": 9.8, "cvss_v2": None},
            {"source": "ghsa", "severity": "HIGH", "cvss_v3": 7.5, "cvss_v2": None},
        ]
        assert body["severity_consensus"] == "CRITICAL"
        assert body["severity_disagreement"] is True

    def test_cve_lookup_consensus_tie_resolves_to_highest_severity(self):
        from db import upsert_cve

        upsert_cve(
            {
                "cve_id": "CVE-2099-7104",
                "description": "Tie-break highest severity.",
                "severity": "CRITICAL",
                "cvss_v3": 9.8,
                "severity_sources": [
                    {"source": "nvd", "severity": "CRITICAL", "cvss_v3": 9.8, "cvss_v2": None},
                    {"source": "ghsa", "severity": "HIGH", "cvss_v3": 7.5, "cvss_v2": None},
                ],
                "in_kev": 0,
                "refs": [],
                "summary": "test",
            }
        )
        r = client.get("/v1/cve/CVE-2099-7104?include_severity_breakdown=true")
        body = r.json()
        assert body["severity_consensus"] == "CRITICAL", "1-1 tie must pick highest severity (CRITICAL > HIGH)"

    def test_cve_lookup_consensus_majority_wins_when_no_tie(self):
        from db import upsert_cve

        upsert_cve(
            {
                "cve_id": "CVE-2099-7105",
                "description": "Majority wins.",
                "severity": "HIGH",
                "cvss_v3": 7.5,
                "severity_sources": [
                    {"source": "nvd", "severity": "HIGH", "cvss_v3": 7.5, "cvss_v2": None},
                    {"source": "mitre", "severity": "HIGH", "cvss_v3": 7.5, "cvss_v2": None},
                    {"source": "ghsa", "severity": "MEDIUM", "cvss_v3": 5.5, "cvss_v2": None},
                ],
                "in_kev": 0,
                "refs": [],
                "summary": "test",
            }
        )
        r = client.get("/v1/cve/CVE-2099-7105?include_severity_breakdown=true")
        body = r.json()
        assert body["severity_consensus"] == "HIGH"
        assert body["severity_disagreement"] is True

    def test_cve_lookup_disagreement_fires_on_v2_vs_v3_bucket_diff(self):
        from db import upsert_cve

        upsert_cve(
            {
                "cve_id": "CVE-2099-7106",
                "description": "v2-vs-v3 disagreement.",
                "severity": "MEDIUM",
                "cvss_v3": 5.5,
                "cvss_v2": 7.5,
                "severity_sources": [
                    {"source": "nvd", "severity": "MEDIUM", "cvss_v3": 5.5, "cvss_v2": 7.5},
                ],
                "in_kev": 0,
                "refs": [],
                "summary": "test",
            }
        )
        r = client.get("/v1/cve/CVE-2099-7106?include_severity_breakdown=true")
        body = r.json()
        assert body["severity_disagreement"] is True, (
            "single-source v2 HIGH vs v3 MEDIUM must trigger any-version disagreement"
        )

    def test_bulk_cve_lookup_propagates_severity_breakdown_flag(self):
        from db import upsert_cve

        upsert_cve(
            {
                "cve_id": "CVE-2099-7107",
                "description": "Bulk pass-through.",
                "severity": "HIGH",
                "cvss_v3": 7.5,
                "severity_sources": [
                    {"source": "nvd", "severity": "HIGH", "cvss_v3": 7.5, "cvss_v2": None},
                ],
                "in_kev": 0,
                "refs": [],
                "summary": "test",
            }
        )
        r = client.post(
            "/v1/cves/bulk",
            json={"cve_ids": ["CVE-2099-7107"], "include_severity_breakdown": True},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["results"][0]["cve"]["severity_sources"] == [
            {"source": "nvd", "severity": "HIGH", "cvss_v3": 7.5, "cvss_v2": None},
        ]

    def test_cache_key_versioning_separates_severity_breakdown_flag_variants(self):
        from db import upsert_cve

        upsert_cve(
            {
                "cve_id": "CVE-2099-7108",
                "description": "4-flag bitmask.",
                "severity": "HIGH",
                "cvss_v3": 7.5,
                "severity_sources": [
                    {"source": "nvd", "severity": "HIGH", "cvss_v3": 7.5, "cvss_v2": None},
                    {"source": "ghsa", "severity": "MEDIUM", "cvss_v3": 5.5, "cvss_v2": None},
                ],
                "in_kev": 0,
                "refs": [],
                "summary": "test",
            }
        )
        # First with flag false (default) — must NOT include severity_sources
        r1 = client.get("/v1/cve/CVE-2099-7108")
        assert "severity_sources" not in r1.json()
        # Now with flag true — must include them, despite default cache being warm
        r2 = client.get("/v1/cve/CVE-2099-7108?include_severity_breakdown=true")
        assert "severity_sources" in r2.json(), (
            "4-flag cache key must serve fresh response when severity_breakdown flag flips"
        )
        assert len(r2.json()["severity_sources"]) == 2

    def test_deserialize_cve_handles_malformed_severity_sources_json(self):
        """Fold-in (security-review MED-1, CWE-209): corrupt severity_sources JSON in DB
        must not raise (which would surface a 500 + stack trace). _deserialize_cve
        catches JSONDecodeError and returns None instead."""
        from db import get_cve, get_cve_db

        with get_cve_db() as con:
            con.execute(
                "INSERT OR REPLACE INTO cves (cve_id, severity_sources) VALUES (?, ?)",
                ("CVE-2099-7199", "{not valid json"),
            )
        row = get_cve("CVE-2099-7199")
        assert row is not None
        assert row["severity_sources"] is None, "malformed severity_sources JSON must degrade to None, not raise"


class TestCveLeadingPivotHints:
    """Batch 5a: cve_leading emits cve_lookup + calculate_risk_score per top-5; +kev_detail when any KEV present."""

    def test_cve_leading_pivot_emits_per_item_lookup_and_risk_score(self):
        from cve.routes import _cve_leading_pivot_hints

        results = [
            {"cve_id": "CVE-2024-0001", "kev": {"in_kev": False}},
            {"cve_id": "CVE-2024-0002", "kev": {"in_kev": False}},
        ]
        hints = _cve_leading_pivot_hints(results)
        tools = [h.tool for h in hints]
        assert tools == ["cve_lookup", "calculate_risk_score", "cve_lookup", "calculate_risk_score"]
        inputs = [h.input for h in hints]
        assert inputs == ["CVE-2024-0001", "CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0002"]
        for h in hints:
            assert h.reason

    def test_cve_leading_pivot_caps_at_top_5_results(self):
        from cve.routes import _cve_leading_pivot_hints

        results = [{"cve_id": f"CVE-2024-{i:04d}", "kev": {"in_kev": False}} for i in range(10)]
        hints = _cve_leading_pivot_hints(results)
        cve_lookup_inputs = [h.input for h in hints if h.tool == "cve_lookup"]
        assert cve_lookup_inputs == [
            "CVE-2024-0000",
            "CVE-2024-0001",
            "CVE-2024-0002",
            "CVE-2024-0003",
            "CVE-2024-0004",
        ]
        assert len([h for h in hints if h.tool == "calculate_risk_score"]) == 5

    def test_cve_leading_pivot_appends_kev_detail_when_in_kev(self):
        from cve.routes import _cve_leading_pivot_hints

        results = [
            {"cve_id": "CVE-2024-0001", "kev": {"in_kev": False}},
            {"cve_id": "CVE-2021-44228", "kev": {"in_kev": True}},
        ]
        hints = _cve_leading_pivot_hints(results)
        kev_hints = [h for h in hints if h.tool == "kev_detail"]
        assert len(kev_hints) == 1
        assert kev_hints[0].input == "CVE-2021-44228"

    def test_cve_leading_pivot_empty_on_no_results(self):
        from cve.routes import _cve_leading_pivot_hints

        assert _cve_leading_pivot_hints([]) == []


class TestBulkCveLookupOuterHints:
    """Batch 5a: bulk_cve_lookup outer envelope emits exploit_lookup (high-severity) + kev_detail (in_kev). Per-item hints unaffected."""

    def test_bulk_cve_outer_emits_exploit_when_high_severity(self):
        from cve.routes import _bulk_cve_lookup_outer_hints

        results = [
            {
                "cve_id": "CVE-2021-44228",
                "status": "ok",
                "cve": {"cve_id": "CVE-2021-44228", "cvss_v3": 9.8, "kev": {"in_kev": False}},
            },
        ]
        hints = _bulk_cve_lookup_outer_hints(results)
        tools = [h.tool for h in hints]
        assert "exploit_lookup" in tools
        exploit_hint = next(h for h in hints if h.tool == "exploit_lookup")
        assert exploit_hint.input == "CVE-2021-44228"
        assert exploit_hint.reason

    def test_bulk_cve_outer_emits_kev_detail_when_in_kev(self):
        from cve.routes import _bulk_cve_lookup_outer_hints

        results = [
            {
                "cve_id": "CVE-2024-3094",
                "status": "ok",
                "cve": {"cve_id": "CVE-2024-3094", "cvss_v3": 5.0, "kev": {"in_kev": True}},
            },
        ]
        hints = _bulk_cve_lookup_outer_hints(results)
        tools = [h.tool for h in hints]
        assert tools == ["kev_detail"]
        assert hints[0].input == "CVE-2024-3094"

    def test_bulk_cve_outer_empty_when_all_below_severity_threshold(self):
        from cve.routes import _bulk_cve_lookup_outer_hints

        results = [
            {
                "cve_id": "CVE-2024-0001",
                "status": "ok",
                "cve": {"cve_id": "CVE-2024-0001", "cvss_v3": 3.5, "kev": {"in_kev": False}},
            },
        ]
        hints = _bulk_cve_lookup_outer_hints(results)
        assert hints == []

    def test_bulk_cve_outer_empty_when_all_failed_or_not_found(self):
        from cve.routes import _bulk_cve_lookup_outer_hints

        results = [
            {"cve_id": "CVE-9999-99999", "status": "not_found", "cve": None, "error": "CVE not found"},
            {"cve_id": "CVE-INVALID", "status": "invalid_format", "cve": None, "error": "Invalid"},
        ]
        hints = _bulk_cve_lookup_outer_hints(results)
        assert hints == []


class TestGhsaDeltaCheckpointSelfPin:
    """S253: sync_ghsa must not self-pin. An advisory whose updated_at EQUALS
    the checkpoint must be processed (idempotent), not trigger an immediate
    stop that freezes the checkpoint and processes 0 forever."""

    def test_boundary_equal_advisory_processed_older_stops(self):
        import asyncio
        from unittest.mock import MagicMock, patch

        from cve import sync as ghsa_sync

        PIN = "2026-05-17T21:17:01Z"
        advisories = [
            {"cve_id": "CVE-2026-45106", "updated_at": PIN, "html_url": "https://github.com/advisories/GHSA-6wxc"},
            {
                "cve_id": "CVE-2026-40000",
                "updated_at": "2026-05-10T00:00:00Z",
                "html_url": "https://github.com/advisories/GHSA-old",
            },
        ]

        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json = MagicMock(return_value=advisories)
        resp.headers = {}

        async def fake_get(url, params=None, headers=None, timeout=None):
            return resp

        recorded = {}

        def fake_update_status(source, count, status="ok", checkpoint=None):
            recorded["count"] = count
            recorded["checkpoint"] = checkpoint

        with (
            patch.object(ghsa_sync._client, "get", side_effect=fake_get),
            patch.object(ghsa_sync, "get_sync_checkpoint", return_value=PIN),
            patch.object(ghsa_sync, "update_sync_status", side_effect=fake_update_status),
            patch.object(ghsa_sync, "_github_headers", return_value={}),
            patch.object(ghsa_sync, "_parse_ghsa_advisory", side_effect=lambda a: {"cve_id": a["cve_id"]}),
            patch.object(ghsa_sync, "upsert_cve_if_absent", MagicMock(return_value=True)) as mock_upsert,
            patch.object(ghsa_sync, "record_cve_source", MagicMock()) as mock_record,
        ):
            count = asyncio.run(ghsa_sync.sync_ghsa())

        # Boundary advisory (updated_at == checkpoint) MUST be processed;
        # the genuinely-older one (updated_at < checkpoint) MUST stop the walk.
        assert count == 1, f"expected 1 (boundary processed, older stops), got {count}"
        assert mock_upsert.call_count == 1
        mock_record.assert_called_once_with("CVE-2026-45106", "ghsa", advisories[0]["html_url"])
        assert recorded["count"] == 1
