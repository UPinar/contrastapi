"""Regression tests for the v1.22.3 review round 2 fix pass.

CRIT (round 2): _coerce_retry_after must catch OverflowError + reject bool/inf/nan.
HIGH (round 2): shortcuts must re-raise TransportError (not swallow MITM/network failures).
MED (round 2): items→results in 4 search responses (already validated by namespace tests).
MED (round 2): CVE regex \\d{3,} (was \\d{4,}) — CVE-2024-123 is valid per NVD spec.
CRIT (round 2): TypedDict field names match server schemas — runtime key-access tests below.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from contrastapi import ContrastAPI, TransportError, audit_full, enrich_batch, triage_ioc
from contrastapi.exceptions import _coerce_retry_after

# ---------------------------------------------------------------------------
# CRIT: _coerce_retry_after edge cases (OverflowError + bool + inf/nan)
# ---------------------------------------------------------------------------


def test_retry_after_bool_true_dropped_not_silently_treated_as_one():
    """`int(True) == 1` would silently produce 1-second sleeps. Must drop."""
    assert _coerce_retry_after(True) is None


def test_retry_after_bool_false_dropped():
    assert _coerce_retry_after(False) is None


def test_retry_after_float_inf_dropped():
    assert _coerce_retry_after(float("inf")) is None


def test_retry_after_float_neg_inf_dropped():
    assert _coerce_retry_after(float("-inf")) is None


def test_retry_after_float_nan_dropped():
    assert _coerce_retry_after(float("nan")) is None


def test_retry_after_huge_float_clamped_not_overflowed():
    """A very large but finite float must clamp, not raise OverflowError."""
    assert _coerce_retry_after(1e10) == 3600


def test_retry_after_normal_float_truncated_to_int():
    assert _coerce_retry_after(60.7) == 60


# ---------------------------------------------------------------------------
# HIGH: shortcuts must re-raise TransportError (network/MITM signal)
# ---------------------------------------------------------------------------


@respx.mock
def test_triage_ioc_propagates_transport_error():
    """Application errors are swallowed to "errors" dict; transport failures bubble."""
    respx.get("https://api.contrastcyber.com/v1/ioc/8.8.8.8").mock(side_effect=httpx.ConnectError("DNS poisoned"))
    with ContrastAPI() as client, pytest.raises(TransportError, match="DNS poisoned"):
        triage_ioc(client, "8.8.8.8")


@respx.mock
def test_audit_full_propagates_transport_error():
    respx.get("https://api.contrastcyber.com/v1/audit/example.com").mock(
        side_effect=httpx.ConnectError("connection refused")
    )
    with ContrastAPI() as client, pytest.raises(TransportError):
        audit_full(client, "example.com")


@respx.mock
def test_enrich_batch_propagates_transport_error():
    respx.post("https://api.contrastcyber.com/v1/cves/bulk").mock(
        side_effect=httpx.ConnectError("TLS handshake failed")
    )
    with ContrastAPI() as client, pytest.raises(TransportError):
        enrich_batch(client, ["CVE-2021-44228"])


@respx.mock
def test_triage_ioc_application_error_still_swallowed():
    """4xx/5xx application errors keep the partial-success behaviour."""
    respx.get("https://api.contrastcyber.com/v1/ioc/8.8.8.8").mock(
        return_value=httpx.Response(200, json={"verdict": "clean"})
    )
    respx.get("https://api.contrastcyber.com/v1/threat-report/8.8.8.8").mock(
        return_value=httpx.Response(
            429,
            json={"error": {"code": "rate_limit_exceeded", "message": "Pro only"}},
        )
    )
    with ContrastAPI() as client:
        result = triage_ioc(client, "8.8.8.8")
    assert "ioc" in result
    assert result["errors"] == {"threat_report": "Pro only"}


# ---------------------------------------------------------------------------
# MED: enrich_batch CVE regex \\d{3,} (was \\d{4,})
# ---------------------------------------------------------------------------


@respx.mock
def test_enrich_batch_three_digit_cve_routes_to_cve():
    """CVE-2024-123 is a valid NVD identifier (3-digit suffix). Must route to cve.bulk."""
    respx.post("https://api.contrastcyber.com/v1/cves/bulk").mock(
        return_value=httpx.Response(200, json={"successful": 1, "results": []})
    )
    with ContrastAPI() as client:
        result = enrich_batch(client, ["CVE-2024-123"])
    assert result["routed"]["cve"] == ["CVE-2024-123"]
    assert result["routed"]["ioc"] == []


@respx.mock
def test_enrich_batch_two_digit_cve_routes_to_ioc():
    """CVE-2024-12 (2-digit suffix) doesn't match the spec — routes to IOC bucket."""
    respx.post("https://api.contrastcyber.com/v1/iocs/bulk").mock(
        return_value=httpx.Response(200, json={"successful": 0, "results": []})
    )
    with ContrastAPI() as client:
        result = enrich_batch(client, ["CVE-2024-12"])
    assert result["routed"]["cve"] == []
    assert result["routed"]["ioc"] == ["CVE-2024-12"]


# ---------------------------------------------------------------------------
# CRIT: TypedDict field-name parity with server (runtime key-access tests)
# ---------------------------------------------------------------------------


@respx.mock
def test_atlas_case_study_typeddict_has_techniques_used_not_techniques():
    """Server returns `techniques_used`; SDK consumers must access that key."""
    respx.get("https://api.contrastcyber.com/v1/atlas/case-studies/AML.CS0001").mock(
        return_value=httpx.Response(
            200,
            json={
                "case_study_id": "AML.CS0001",
                "name": "Test",
                "description": "Narrative summary",
                "techniques_used": ["AML.T0051", "AML.T0043"],
            },
        )
    )
    with ContrastAPI() as client:
        cs = client.atlas.case_study("AML.CS0001")
    # All four canonical fields must be accessible without KeyError
    assert cs["case_study_id"] == "AML.CS0001"
    assert cs["name"] == "Test"
    assert cs["description"] == "Narrative summary"
    assert cs["techniques_used"] == ["AML.T0051", "AML.T0043"]


@respx.mock
def test_d3fend_defense_typeddict_uses_singular_tactic_and_artifact():
    """Server returns `tactic` (singular) + `artifact` (singular) + `label` (not name)."""
    respx.get("https://api.contrastcyber.com/v1/d3fend/CertificatePinning").mock(
        return_value=httpx.Response(
            200,
            json={
                "defense_id": "CertificatePinning",
                "label": "Certificate Pinning",
                "uri": "http://d3fend.mitre.org/ontologies/d3fend.owl#CertificatePinning",
                "parent_label": "Credential Hardening",
                "description": "Pin certs to known fingerprints",
                "tactic": "Harden",
                "artifact": "Certificate",
                "attack_techniques": ["T1550.001", "T1539"],
            },
        )
    )
    with ContrastAPI() as client:
        d = client.d3fend.defense("CertificatePinning")
    assert d["label"] == "Certificate Pinning"
    assert d["tactic"] == "Harden"
    assert d["artifact"] == "Certificate"
    assert d["attack_techniques"] == ["T1550.001", "T1539"]
    assert d["uri"].startswith("http://d3fend.mitre.org/")
    assert d["parent_label"] == "Credential Hardening"


@respx.mock
def test_atlas_technique_typeddict_has_attack_reference_id_subtechnique_of():
    """Server returns attack_reference_id, subtechnique_of, created_date, modified_date."""
    respx.get("https://api.contrastcyber.com/v1/atlas/AML.T0051").mock(
        return_value=httpx.Response(
            200,
            json={
                "technique_id": "AML.T0051",
                "name": "LLM Prompt Injection",
                "description": "Adversary crafts prompts to manipulate LLM output.",
                "tactics": ["AML.TA0011"],
                "maturity": "demonstrated",
                "attack_reference_id": "T1059",
                "attack_reference_url": "https://attack.mitre.org/techniques/T1059/",
                "subtechnique_of": None,
                "created_date": "2023-03-30",
                "modified_date": "2024-10-08",
            },
        )
    )
    with ContrastAPI() as client:
        t = client.atlas.technique("AML.T0051")
    assert t["technique_id"] == "AML.T0051"
    assert t["attack_reference_id"] == "T1059"
    assert t["created_date"] == "2023-03-30"
    assert t["modified_date"] == "2024-10-08"


@respx.mock
def test_search_typeddicts_use_results_not_items():
    """All 4 search responses (cve_search, atlas search, d3fend search, d3fend_for_attack)
    use the server's `results` key, not `items`."""
    respx.get("https://api.contrastcyber.com/v1/cves").mock(
        return_value=httpx.Response(200, json={"count": 1, "total": 1, "results": [{"cve_id": "CVE-2021-44228"}]})
    )
    respx.get("https://api.contrastcyber.com/v1/atlas/techniques").mock(
        return_value=httpx.Response(200, json={"total": 1, "results": [{"technique_id": "AML.T0051"}]})
    )
    respx.get("https://api.contrastcyber.com/v1/d3fend/defenses").mock(
        return_value=httpx.Response(200, json={"total": 1, "results": [{"defense_id": "CertificatePinning"}]})
    )
    respx.get("https://api.contrastcyber.com/v1/d3fend/attack/T1059").mock(
        return_value=httpx.Response(
            200,
            json={
                "attack_technique_id": "T1059",
                "total": 1,
                "defenses": [{"defense_id": "ProcessAllowlist"}],
            },
        )
    )
    with ContrastAPI() as client:
        cves = client.cve.search()
        atlas = client.atlas.technique_search()
        d3 = client.d3fend.defense_search()
        att = client.d3fend.defense_for_attack("T1059")
    # All return `results` not `items`
    assert cves["results"][0]["cve_id"] == "CVE-2021-44228"
    assert atlas["results"][0]["technique_id"] == "AML.T0051"
    assert d3["results"][0]["defense_id"] == "CertificatePinning"
    # d3fend_for_attack uses `defenses` not `results` per server schema
    assert att["defenses"][0]["defense_id"] == "ProcessAllowlist"


@respx.mock
def test_cve_typeddict_uses_cwe_id_singular_not_cwe_ids():
    """Server schema has cwe_id (singular string), not cwe_ids (list)."""
    respx.get("https://api.contrastcyber.com/v1/cve/CVE-2021-44228").mock(
        return_value=httpx.Response(
            200,
            json={
                "cve_id": "CVE-2021-44228",
                "cwe_id": "CWE-502",
                "cvss_v3": 10.0,
                "kev": {"in_kev": True},
                "epss": {"score": 0.97},
            },
        )
    )
    with ContrastAPI() as client:
        cve = client.cve.lookup("CVE-2021-44228")
    assert cve["cwe_id"] == "CWE-502"
    assert cve["cvss_v3"] == 10.0
    assert cve["kev"]["in_kev"] is True


@respx.mock
def test_ioc_typeddict_uses_type_and_threat_level():
    """Server returns `type` (not kind) + `threat_level` (not verdict_label)."""
    respx.get("https://api.contrastcyber.com/v1/ioc/8.8.8.8").mock(
        return_value=httpx.Response(
            200,
            json={
                "indicator": "8.8.8.8",
                "type": "ip",
                "threat_level": "none",
                "sources": {},
            },
        )
    )
    with ContrastAPI() as client:
        ioc = client.ioc.lookup("8.8.8.8")
    assert ioc["type"] == "ip"
    assert ioc["threat_level"] == "none"


@respx.mock
def test_kev_typeddict_full_field_set():
    """KEV response has known_ransomware_use, vendor_project, vulnerability_name, cwes, etc."""
    respx.get("https://api.contrastcyber.com/v1/kev/CVE-2021-44228").mock(
        return_value=httpx.Response(
            200,
            json={
                "cve_id": "CVE-2021-44228",
                "in_kev": True,
                "date_added": "2021-12-10",
                "due_date": "2021-12-24",
                "vendor_project": "Apache",
                "product": "Log4j2",
                "vulnerability_name": "Log4Shell",
                "short_description": "RCE via JNDI lookup.",
                "required_action": "Apply updates per vendor instructions.",
                "known_ransomware_use": True,
                "notes": "https://logging.apache.org/log4j/2.x/security.html",
                "cwes": ["CWE-20", "CWE-400"],
            },
        )
    )
    with ContrastAPI() as client:
        kev = client.cve.kev("CVE-2021-44228")
    assert kev["vendor_project"] == "Apache"
    assert kev["vulnerability_name"] == "Log4Shell"
    assert kev["known_ransomware_use"] is True
    assert kev["cwes"] == ["CWE-20", "CWE-400"]


@respx.mock
def test_password_typeddict_uses_hash_prefix_and_pwned_count():
    """Server returns hash_prefix + found + pwned_count (not just `pwned`)."""
    sha = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
    respx.get(f"https://api.contrastcyber.com/v1/password/{sha}").mock(
        return_value=httpx.Response(
            200,
            json={
                "hash_prefix": sha[:5],
                "found": True,
                "pwned_count": 12345,
                "summary": "Password seen in 12345 breaches",
            },
        )
    )
    with ContrastAPI() as client:
        pw = client.password.check(sha)
    assert pw["hash_prefix"] == sha[:5]
    assert pw["found"] is True
    assert pw["pwned_count"] == 12345


@respx.mock
def test_ip_typeddict_has_severity_label_and_tor_exit():
    """Server schema includes severity_label, tor_exit, cloud_provider, vulns enriched."""
    respx.get("https://api.contrastcyber.com/v1/ip/8.8.8.8").mock(
        return_value=httpx.Response(
            200,
            json={
                "ip": "8.8.8.8",
                "ptr": "dns.google",
                "asn": 15169,
                "asn_name": "GOOGLE",
                "country": "US",
                "ports": [53, 443],
                "is_datacenter": True,
                "tor_exit": False,
                "cloud_provider": "Google",
                "risk_score": 10,
                "severity_label": "low",
            },
        )
    )
    with ContrastAPI() as client:
        ip = client.ip.lookup("8.8.8.8")
    assert ip["severity_label"] == "low"
    assert ip["tor_exit"] is False
    assert ip["cloud_provider"] == "Google"
    assert ip["is_datacenter"] is True
