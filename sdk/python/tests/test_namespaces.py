"""Per-namespace tests — exercises URL construction + body shape for each method."""

from __future__ import annotations

import httpx
import pytest
import respx
from contrastapi import ContrastAPI

# ---------------------------------------------------------------------------
# CVE
# ---------------------------------------------------------------------------


@respx.mock
def test_cve_lookup_url():
    route = respx.get("https://api.contrastcyber.com/v1/cve/CVE-2021-44228").mock(
        return_value=httpx.Response(200, json={"cve_id": "CVE-2021-44228"})
    )
    with ContrastAPI() as client:
        client.cve.lookup("CVE-2021-44228")
    assert route.called


@respx.mock
def test_cve_search_query_params():
    route = respx.get("https://api.contrastcyber.com/v1/cves").mock(
        return_value=httpx.Response(200, json={"items": []})
    )
    with ContrastAPI() as client:
        client.cve.search(product="apache", severity="critical", days=7, limit=10)
    qs = dict(route.calls.last.request.url.params)
    assert qs == {"product": "apache", "severity": "critical", "days": "7", "limit": "10"}


@respx.mock
def test_cve_search_no_params_omits_query_string():
    route = respx.get("https://api.contrastcyber.com/v1/cves").mock(
        return_value=httpx.Response(200, json={"items": []})
    )
    with ContrastAPI() as client:
        client.cve.search()
    assert dict(route.calls.last.request.url.params) == {}


@respx.mock
def test_cve_leading_url_and_params():
    route = respx.get("https://api.contrastcyber.com/v1/cve/leading").mock(
        return_value=httpx.Response(200, json={"items": []})
    )
    with ContrastAPI() as client:
        client.cve.leading(limit=5, include="full")
    qs = dict(route.calls.last.request.url.params)
    assert qs == {"limit": "5", "include": "full"}


@respx.mock
def test_cve_kev_url():
    route = respx.get("https://api.contrastcyber.com/v1/kev/CVE-2021-44228").mock(
        return_value=httpx.Response(200, json={"in_kev": True})
    )
    with ContrastAPI() as client:
        client.cve.kev("CVE-2021-44228")
    assert route.called


@respx.mock
def test_cve_exploit_url():
    route = respx.get("https://api.contrastcyber.com/v1/exploit/CVE-2021-44228").mock(
        return_value=httpx.Response(200, json={"exploits": []})
    )
    with ContrastAPI() as client:
        client.cve.exploit("CVE-2021-44228")
    assert route.called


@respx.mock
def test_cve_bulk_post_body():
    route = respx.post("https://api.contrastcyber.com/v1/cves/bulk").mock(
        return_value=httpx.Response(200, json={"successful": 2, "results": []})
    )
    with ContrastAPI() as client:
        client.cve.bulk(["CVE-2021-44228", "CVE-2024-3094"])
    body = route.calls.last.request.read()
    assert b"cve_ids" in body
    assert b"CVE-2021-44228" in body


def test_cve_bulk_rejects_non_list():
    with ContrastAPI() as client, pytest.raises(ValueError, match="cve_ids"):
        client.cve.bulk("CVE-2021-44228")  # type: ignore[arg-type]


def test_cve_bulk_rejects_non_string_items():
    with ContrastAPI() as client, pytest.raises(ValueError, match="cve_ids"):
        client.cve.bulk(["CVE-2021-44228", 12345])  # type: ignore[list-item]


def test_cve_lookup_rejects_empty_id():
    with ContrastAPI() as client, pytest.raises(ValueError, match="Missing"):
        client.cve.lookup("")


# ---------------------------------------------------------------------------
# CWE
# ---------------------------------------------------------------------------


@respx.mock
def test_cwe_lookup_url():
    route = respx.get("https://api.contrastcyber.com/v1/cwe/CWE-79").mock(
        return_value=httpx.Response(200, json={"cwe_id": "CWE-79"})
    )
    with ContrastAPI() as client:
        client.cwe.lookup("CWE-79")
    assert route.called


# ---------------------------------------------------------------------------
# IOC
# ---------------------------------------------------------------------------


@respx.mock
def test_ioc_lookup_url_with_ip():
    route = respx.get("https://api.contrastcyber.com/v1/ioc/8.8.8.8").mock(
        return_value=httpx.Response(200, json={"indicator": "8.8.8.8"})
    )
    with ContrastAPI() as client:
        client.ioc.lookup("8.8.8.8")
    assert route.called


@respx.mock
def test_ioc_hash_url():
    sha = "44d88612fea8a8f36de82e1278abb02f"
    route = respx.get(f"https://api.contrastcyber.com/v1/hash/{sha}").mock(
        return_value=httpx.Response(200, json={"hash": sha})
    )
    with ContrastAPI() as client:
        client.ioc.hash(sha)
    assert route.called


@respx.mock
def test_ioc_phishing_preserves_path_separators():
    """URL-typed indicators keep `/` boundaries through the path encoder."""
    target = "evil.example.com/login"
    route = respx.get(f"https://api.contrastcyber.com/v1/phishing/{target}").mock(
        return_value=httpx.Response(200, json={"verdict": "phishing"})
    )
    with ContrastAPI() as client:
        client.ioc.phishing(target)
    request_url = str(route.calls.last.request.url)
    assert "evil.example.com/login" in request_url


@respx.mock
def test_ioc_bulk_post_body():
    route = respx.post("https://api.contrastcyber.com/v1/iocs/bulk").mock(
        return_value=httpx.Response(200, json={"successful": 1, "results": []})
    )
    with ContrastAPI() as client:
        client.ioc.bulk(["8.8.8.8", "evil.com"])
    body = route.calls.last.request.read()
    assert b"indicators" in body


def test_ioc_bulk_validation():
    with ContrastAPI() as client, pytest.raises(ValueError, match="indicators"):
        client.ioc.bulk("8.8.8.8")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# ATLAS
# ---------------------------------------------------------------------------


@respx.mock
def test_atlas_technique_url():
    route = respx.get("https://api.contrastcyber.com/v1/atlas/AML.T0051").mock(
        return_value=httpx.Response(200, json={"technique_id": "AML.T0051"})
    )
    with ContrastAPI() as client:
        client.atlas.technique("AML.T0051")
    assert route.called


@respx.mock
def test_atlas_technique_search_with_filters():
    route = respx.get("https://api.contrastcyber.com/v1/atlas/techniques").mock(
        return_value=httpx.Response(200, json={"items": []})
    )
    with ContrastAPI() as client:
        client.atlas.technique_search(keyword="prompt", tactic="ml-attack-staging", maturity="realized", limit=5)
    qs = dict(route.calls.last.request.url.params)
    assert qs == {
        "keyword": "prompt",
        "tactic": "ml-attack-staging",
        "maturity": "realized",
        "limit": "5",
    }


@respx.mock
def test_atlas_bulk_technique_lookup():
    route = respx.post("https://api.contrastcyber.com/v1/atlas/techniques/bulk").mock(
        return_value=httpx.Response(200, json={"successful": 2, "results": []})
    )
    with ContrastAPI() as client:
        client.atlas.bulk_technique_lookup(["AML.T0051", "AML.T0043"])
    body = route.calls.last.request.read()
    assert b"technique_ids" in body
    assert b"AML.T0051" in body


@respx.mock
def test_atlas_case_study_url():
    route = respx.get("https://api.contrastcyber.com/v1/atlas/case-studies/AML.CS0001").mock(
        return_value=httpx.Response(200, json={"case_study_id": "AML.CS0001"})
    )
    with ContrastAPI() as client:
        client.atlas.case_study("AML.CS0001")
    assert route.called


@respx.mock
def test_atlas_case_study_search_with_target_type():
    route = respx.get("https://api.contrastcyber.com/v1/atlas/case-studies").mock(
        return_value=httpx.Response(200, json={"items": []})
    )
    with ContrastAPI() as client:
        client.atlas.case_study_search(target_type="LLM", limit=10)
    qs = dict(route.calls.last.request.url.params)
    assert qs == {"target_type": "LLM", "limit": "10"}


def test_atlas_bulk_validation():
    with ContrastAPI() as client, pytest.raises(ValueError, match="technique_ids"):
        client.atlas.bulk_technique_lookup("AML.T0051")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# D3FEND
# ---------------------------------------------------------------------------


@respx.mock
def test_d3fend_defense_url():
    route = respx.get("https://api.contrastcyber.com/v1/d3fend/CertificatePinning").mock(
        return_value=httpx.Response(200, json={"defense_id": "CertificatePinning"})
    )
    with ContrastAPI() as client:
        client.d3fend.defense("CertificatePinning")
    assert route.called


@respx.mock
def test_d3fend_defense_search_with_filters():
    route = respx.get("https://api.contrastcyber.com/v1/d3fend/defenses").mock(
        return_value=httpx.Response(200, json={"items": []})
    )
    with ContrastAPI() as client:
        client.d3fend.defense_search(keyword="encryption", artifact="Certificate", limit=10)
    qs = dict(route.calls.last.request.url.params)
    assert qs == {"keyword": "encryption", "artifact": "Certificate", "limit": "10"}


@respx.mock
def test_d3fend_defense_for_attack_url_and_params():
    route = respx.get("https://api.contrastcyber.com/v1/d3fend/attack/T1059").mock(
        return_value=httpx.Response(200, json={"defenses": []})
    )
    with ContrastAPI() as client:
        client.d3fend.defense_for_attack("T1059", include="full", exclude_id="ProcessAllowlist")
    qs = dict(route.calls.last.request.url.params)
    assert qs == {"include": "full", "exclude_id": "ProcessAllowlist"}


@respx.mock
def test_d3fend_coverage_post_body():
    route = respx.post("https://api.contrastcyber.com/v1/d3fend/coverage").mock(
        return_value=httpx.Response(200, json={"covered": [], "undefended": []})
    )
    with ContrastAPI() as client:
        client.d3fend.coverage(["T1059", "T1190"])
    body = route.calls.last.request.read()
    assert b"attack_technique_ids" in body
    assert b"T1059" in body


def test_d3fend_coverage_validation():
    with ContrastAPI() as client, pytest.raises(ValueError, match="attack_technique_ids"):
        client.d3fend.coverage("T1059")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Meta
# ---------------------------------------------------------------------------


@respx.mock
def test_status_endpoint():
    route = respx.get("https://api.contrastcyber.com/v1/status").mock(
        return_value=httpx.Response(200, json={"status": "ok", "version": "1.22.5"})
    )
    with ContrastAPI() as client:
        result = client.status()
    assert route.called
    assert result["status"] == "ok"


@respx.mock
def test_usage_endpoint():
    route = respx.get("https://api.contrastcyber.com/v1/usage").mock(
        return_value=httpx.Response(200, json={"requests_remaining": 999})
    )
    with ContrastAPI() as client:
        client.usage()
    assert route.called


def test_client_exposes_version_string():
    with ContrastAPI() as client:
        assert client.version == "1.23.0"
