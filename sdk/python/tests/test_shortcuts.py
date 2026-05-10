"""Tests for the high-level shortcut helpers (triage_ioc, audit_full, enrich_batch)."""

from __future__ import annotations

import httpx
import pytest
import respx
from contrastapi import ContrastAPI, audit_full, enrich_batch, triage_ioc
from contrastapi.shortcuts import _classify_ioc

# ---------------------------------------------------------------------------
# _classify_ioc
# ---------------------------------------------------------------------------


def test_classify_ipv4():
    assert _classify_ioc("8.8.8.8") == "ip"


def test_classify_ipv6():
    assert _classify_ioc("2001:4860:4860::8888") == "ip"


def test_classify_md5_hash():
    assert _classify_ioc("44d88612fea8a8f36de82e1278abb02f") == "hash"


def test_classify_sha256_hash():
    assert _classify_ioc("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "hash"


def test_classify_domain():
    assert _classify_ioc("evil.example.com") == "domain"


def test_classify_unknown():
    assert _classify_ioc("???!!!") == "unknown"


# ---------------------------------------------------------------------------
# triage_ioc
# ---------------------------------------------------------------------------


@respx.mock
def test_triage_ip_calls_threat_report():
    respx.get("https://api.contrastcyber.com/v1/ioc/8.8.8.8").mock(
        return_value=httpx.Response(200, json={"verdict": "clean"})
    )
    respx.get("https://api.contrastcyber.com/v1/threat-report/8.8.8.8").mock(
        return_value=httpx.Response(200, json={"abuseipdb_score": 0})
    )
    with ContrastAPI() as client:
        result = triage_ioc(client, "8.8.8.8")
    assert result["kind"] == "ip"
    assert "ioc" in result and "threat_report" in result
    assert result["errors"] == {}


@respx.mock
def test_triage_domain_calls_domain_report():
    respx.get("https://api.contrastcyber.com/v1/ioc/evil.example.com").mock(
        return_value=httpx.Response(200, json={"verdict": "clean"})
    )
    respx.get("https://api.contrastcyber.com/v1/domain/evil.example.com").mock(
        return_value=httpx.Response(200, json={"domain": "evil.example.com"})
    )
    with ContrastAPI() as client:
        result = triage_ioc(client, "evil.example.com")
    assert result["kind"] == "domain"
    assert "ioc" in result and "domain_report" in result


@respx.mock
def test_triage_hash_calls_hash_lookup():
    sha = "44d88612fea8a8f36de82e1278abb02f"
    respx.get(f"https://api.contrastcyber.com/v1/ioc/{sha}").mock(return_value=httpx.Response(200, json={"hash": sha}))
    respx.get(f"https://api.contrastcyber.com/v1/hash/{sha}").mock(
        return_value=httpx.Response(200, json={"sources": []})
    )
    with ContrastAPI() as client:
        result = triage_ioc(client, sha)
    assert result["kind"] == "hash"
    assert "ioc" in result and "hash" in result


@respx.mock
def test_triage_swallows_per_leg_error():
    """If one leg 404s the helper still returns the other leg's result."""
    respx.get("https://api.contrastcyber.com/v1/ioc/8.8.8.8").mock(
        return_value=httpx.Response(200, json={"verdict": "clean"})
    )
    respx.get("https://api.contrastcyber.com/v1/threat-report/8.8.8.8").mock(
        return_value=httpx.Response(404, json={"error": {"code": "not_found", "message": "no enrichment"}})
    )
    with ContrastAPI() as client:
        result = triage_ioc(client, "8.8.8.8")
    assert "ioc" in result
    assert result["errors"] == {"threat_report": "no enrichment"}


# ---------------------------------------------------------------------------
# audit_full
# ---------------------------------------------------------------------------


@respx.mock
def test_audit_full_composes_audit_subdomains_tech_ssl():
    respx.get("https://api.contrastcyber.com/v1/audit/example.com").mock(
        return_value=httpx.Response(200, json={"score": 85})
    )
    respx.get("https://api.contrastcyber.com/v1/subdomains/example.com").mock(
        return_value=httpx.Response(200, json={"subdomains": ["api.example.com", "blog.example.com"]})
    )
    respx.get("https://api.contrastcyber.com/v1/tech/example.com").mock(
        return_value=httpx.Response(200, json={"tech": ["nginx"]})
    )
    respx.get("https://api.contrastcyber.com/v1/ssl/api.example.com").mock(
        return_value=httpx.Response(200, json={"valid": True})
    )
    respx.get("https://api.contrastcyber.com/v1/ssl/blog.example.com").mock(
        return_value=httpx.Response(200, json={"valid": True})
    )
    with ContrastAPI() as client:
        result = audit_full(client, "example.com", ssl_subdomains=2)
    assert result["audit"]["score"] == 85
    assert "api.example.com" in result["ssl"]
    assert "blog.example.com" in result["ssl"]
    assert result["errors"] == {}


@respx.mock
def test_audit_full_caps_ssl_subdomain_count():
    respx.get("https://api.contrastcyber.com/v1/audit/example.com").mock(
        return_value=httpx.Response(200, json={"score": 85})
    )
    respx.get("https://api.contrastcyber.com/v1/subdomains/example.com").mock(
        return_value=httpx.Response(200, json={"subdomains": ["a.example.com", "b.example.com", "c.example.com"]})
    )
    respx.get("https://api.contrastcyber.com/v1/tech/example.com").mock(
        return_value=httpx.Response(200, json={"tech": []})
    )
    respx.get("https://api.contrastcyber.com/v1/ssl/a.example.com").mock(
        return_value=httpx.Response(200, json={"valid": True})
    )
    with ContrastAPI() as client:
        result = audit_full(client, "example.com", ssl_subdomains=1)
    assert len(result["ssl"]) == 1
    assert "a.example.com" in result["ssl"]


@respx.mock
def test_audit_full_zero_ssl_subdomains_skips_ssl_calls():
    respx.get("https://api.contrastcyber.com/v1/audit/example.com").mock(
        return_value=httpx.Response(200, json={"score": 85})
    )
    respx.get("https://api.contrastcyber.com/v1/subdomains/example.com").mock(
        return_value=httpx.Response(200, json={"subdomains": ["api.example.com"]})
    )
    respx.get("https://api.contrastcyber.com/v1/tech/example.com").mock(
        return_value=httpx.Response(200, json={"tech": []})
    )
    with ContrastAPI() as client:
        result = audit_full(client, "example.com", ssl_subdomains=0)
    assert result["ssl"] == {}


def test_audit_full_rejects_negative_ssl_subdomains():
    with ContrastAPI() as client, pytest.raises(ValueError, match="ssl_subdomains"):
        audit_full(client, "example.com", ssl_subdomains=-1)


@respx.mock
def test_audit_full_swallows_subdomain_error():
    """If subdomain enum fails, audit_full continues with audit + tech."""
    respx.get("https://api.contrastcyber.com/v1/audit/example.com").mock(
        return_value=httpx.Response(200, json={"score": 85})
    )
    respx.get("https://api.contrastcyber.com/v1/subdomains/example.com").mock(
        return_value=httpx.Response(504, json={"error": {"code": "upstream_timeout", "message": "crt.sh timed out"}})
    )
    respx.get("https://api.contrastcyber.com/v1/tech/example.com").mock(
        return_value=httpx.Response(200, json={"tech": ["nginx"]})
    )
    with ContrastAPI() as client:
        result = audit_full(client, "example.com")
    assert result["audit"]["score"] == 85
    assert result["tech"]["tech"] == ["nginx"]
    assert "subdomains" in result["errors"]
    assert result["ssl"] == {}


# ---------------------------------------------------------------------------
# enrich_batch
# ---------------------------------------------------------------------------


@respx.mock
def test_enrich_batch_routes_cve_and_ioc_separately():
    respx.post("https://api.contrastcyber.com/v1/cves/bulk").mock(
        return_value=httpx.Response(200, json={"successful": 1, "results": []})
    )
    respx.post("https://api.contrastcyber.com/v1/iocs/bulk").mock(
        return_value=httpx.Response(200, json={"successful": 1, "results": []})
    )
    with ContrastAPI() as client:
        result = enrich_batch(client, ["CVE-2021-44228", "8.8.8.8"])
    assert result["routed"]["cve"] == ["CVE-2021-44228"]
    assert result["routed"]["ioc"] == ["8.8.8.8"]
    assert result["cve"] is not None
    assert result["ioc"] is not None


@respx.mock
def test_enrich_batch_only_cves_skips_ioc_call():
    respx.post("https://api.contrastcyber.com/v1/cves/bulk").mock(
        return_value=httpx.Response(200, json={"successful": 2, "results": []})
    )
    with ContrastAPI() as client:
        result = enrich_batch(client, ["CVE-2021-44228", "CVE-2024-3094"])
    assert result["cve"] is not None
    assert result["ioc"] is None
    assert result["routed"]["ioc"] == []


@respx.mock
def test_enrich_batch_only_iocs_skips_cve_call():
    respx.post("https://api.contrastcyber.com/v1/iocs/bulk").mock(
        return_value=httpx.Response(200, json={"successful": 1, "results": []})
    )
    with ContrastAPI() as client:
        result = enrich_batch(client, ["8.8.8.8"])
    assert result["cve"] is None
    assert result["ioc"] is not None


def test_enrich_batch_validation():
    with ContrastAPI() as client, pytest.raises(ValueError, match="items"):
        enrich_batch(client, "CVE-2021-44228")  # type: ignore[arg-type]


def test_enrich_batch_rejects_non_string_items():
    with ContrastAPI() as client, pytest.raises(ValueError, match="items"):
        enrich_batch(client, ["CVE-2021-44228", 12345])  # type: ignore[list-item]


@respx.mock
def test_enrich_batch_swallows_cve_error():
    respx.post("https://api.contrastcyber.com/v1/cves/bulk").mock(
        return_value=httpx.Response(429, json={"error": {"code": "rate_limit_exceeded", "message": "Limit"}})
    )
    respx.post("https://api.contrastcyber.com/v1/iocs/bulk").mock(
        return_value=httpx.Response(200, json={"successful": 1, "results": []})
    )
    with ContrastAPI() as client:
        result = enrich_batch(client, ["CVE-2021-44228", "8.8.8.8"])
    assert "cve" in result["errors"]
    assert result["ioc"] is not None


@respx.mock
def test_enrich_batch_uppercase_required_for_cve():
    """Lowercase 'cve-...' is treated as IOC (matches Node SDK + server validator).

    Server's bulk_cve route rejects mixed-case anyway; SDK keeps strict regex
    so callers see a clear "no IOC results" instead of a confusing CVE bulk error.
    """
    respx.post("https://api.contrastcyber.com/v1/iocs/bulk").mock(
        return_value=httpx.Response(200, json={"successful": 0, "results": []})
    )
    with ContrastAPI() as client:
        result = enrich_batch(client, ["cve-2021-44228"])
    assert result["routed"]["cve"] == []
    assert result["routed"]["ioc"] == ["cve-2021-44228"]
