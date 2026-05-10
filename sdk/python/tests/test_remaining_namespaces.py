"""URL/body tests for the namespaces added in sub-batch B:
domain, ip, asn, email, phone, password, username, check, scan.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from contrastapi import ContrastAPI

# ---------------------------------------------------------------------------
# Domain
# ---------------------------------------------------------------------------


@respx.mock
def test_domain_report_url():
    route = respx.get("https://api.contrastcyber.com/v1/domain/example.com").mock(
        return_value=httpx.Response(200, json={"domain": "example.com"})
    )
    with ContrastAPI() as client:
        client.domain.report("example.com")
    assert route.called


@respx.mock
def test_domain_report_lite_query():
    route = respx.get("https://api.contrastcyber.com/v1/domain/example.com").mock(
        return_value=httpx.Response(200, json={"domain": "example.com"})
    )
    with ContrastAPI() as client:
        client.domain.report("example.com", lite=True)
    assert "lite=true" in str(route.calls.last.request.url)


@respx.mock
def test_domain_dns_url():
    route = respx.get("https://api.contrastcyber.com/v1/dns/example.com").mock(
        return_value=httpx.Response(200, json={"records": []})
    )
    with ContrastAPI() as client:
        client.domain.dns("example.com")
    assert route.called


@respx.mock
def test_domain_whois_url():
    route = respx.get("https://api.contrastcyber.com/v1/whois/example.com").mock(
        return_value=httpx.Response(200, json={"registrar": "Test"})
    )
    with ContrastAPI() as client:
        client.domain.whois("example.com")
    assert route.called


@respx.mock
def test_domain_subdomains_url():
    route = respx.get("https://api.contrastcyber.com/v1/subdomains/example.com").mock(
        return_value=httpx.Response(200, json={"subdomains": []})
    )
    with ContrastAPI() as client:
        client.domain.subdomains("example.com")
    assert route.called


@respx.mock
def test_domain_certs_url():
    route = respx.get("https://api.contrastcyber.com/v1/certs/example.com").mock(
        return_value=httpx.Response(200, json={"certs": []})
    )
    with ContrastAPI() as client:
        client.domain.certs("example.com")
    assert route.called


@respx.mock
def test_domain_ssl_url():
    route = respx.get("https://api.contrastcyber.com/v1/ssl/example.com").mock(
        return_value=httpx.Response(200, json={"valid": True})
    )
    with ContrastAPI() as client:
        client.domain.ssl("example.com")
    assert route.called


@respx.mock
def test_domain_tech_url():
    route = respx.get("https://api.contrastcyber.com/v1/tech/example.com").mock(
        return_value=httpx.Response(200, json={"tech": []})
    )
    with ContrastAPI() as client:
        client.domain.tech("example.com")
    assert route.called


@respx.mock
def test_domain_threat_url():
    route = respx.get("https://api.contrastcyber.com/v1/threat/example.com").mock(
        return_value=httpx.Response(200, json={"verdict": "clean"})
    )
    with ContrastAPI() as client:
        client.domain.threat("example.com")
    assert route.called


@respx.mock
def test_domain_monitor_url():
    route = respx.get("https://api.contrastcyber.com/v1/monitor/example.com").mock(
        return_value=httpx.Response(200, json={"alerts": []})
    )
    with ContrastAPI() as client:
        client.domain.monitor("example.com")
    assert route.called


@respx.mock
def test_domain_vulns_url():
    route = respx.get("https://api.contrastcyber.com/v1/domain/example.com/vulns").mock(
        return_value=httpx.Response(200, json={"vulns": []})
    )
    with ContrastAPI() as client:
        client.domain.vulns("example.com")
    assert route.called


@respx.mock
def test_domain_audit_url():
    route = respx.get("https://api.contrastcyber.com/v1/audit/example.com").mock(
        return_value=httpx.Response(200, json={"score": 85})
    )
    with ContrastAPI() as client:
        client.domain.audit("example.com")
    assert route.called


@respx.mock
def test_domain_wayback_url():
    route = respx.get("https://api.contrastcyber.com/v1/archive/example.com").mock(
        return_value=httpx.Response(200, json={"snapshots": []})
    )
    with ContrastAPI() as client:
        client.domain.wayback("example.com")
    assert route.called


@respx.mock
def test_domain_bulk_post_body():
    route = respx.post("https://api.contrastcyber.com/v1/domains/bulk").mock(
        return_value=httpx.Response(200, json={"results": []})
    )
    with ContrastAPI() as client:
        client.domain.bulk(["a.com", "b.com"])
    body = route.calls.last.request.read()
    assert b"domains" in body and b"a.com" in body


def test_domain_bulk_validation():
    with ContrastAPI() as client, pytest.raises(ValueError, match="domains"):
        client.domain.bulk("a.com")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# IP / ASN
# ---------------------------------------------------------------------------


@respx.mock
def test_ip_lookup_url():
    route = respx.get("https://api.contrastcyber.com/v1/ip/8.8.8.8").mock(
        return_value=httpx.Response(200, json={"ip": "8.8.8.8"})
    )
    with ContrastAPI() as client:
        client.ip.lookup("8.8.8.8")
    assert route.called


@respx.mock
def test_ip_threat_report_url():
    route = respx.get("https://api.contrastcyber.com/v1/threat-report/1.1.1.1").mock(
        return_value=httpx.Response(200, json={"verdict": "clean"})
    )
    with ContrastAPI() as client:
        client.ip.threat_report("1.1.1.1")
    assert route.called


@respx.mock
def test_asn_lookup_url():
    route = respx.get("https://api.contrastcyber.com/v1/asn/AS15169").mock(
        return_value=httpx.Response(200, json={"asn": 15169})
    )
    with ContrastAPI() as client:
        client.asn.lookup("AS15169")
    assert route.called


# ---------------------------------------------------------------------------
# Email / Phone / Password / Username
# ---------------------------------------------------------------------------


@respx.mock
def test_email_mx_url():
    route = respx.get("https://api.contrastcyber.com/v1/email/mx/example.com").mock(
        return_value=httpx.Response(200, json={"mx": []})
    )
    with ContrastAPI() as client:
        client.email.mx("example.com")
    assert route.called


@respx.mock
def test_email_disposable_url():
    route = respx.get("https://api.contrastcyber.com/v1/email/disposable/foo@mailinator.com").mock(
        return_value=httpx.Response(200, json={"disposable": True})
    )
    with ContrastAPI() as client:
        client.email.disposable("foo@mailinator.com")
    assert route.called


@respx.mock
def test_phone_lookup_url():
    route = respx.get("https://api.contrastcyber.com/v1/phone/+14155552671").mock(
        return_value=httpx.Response(200, json={"valid": True})
    )
    with ContrastAPI() as client:
        client.phone.lookup("+14155552671")
    assert route.called


@respx.mock
def test_password_check_url():
    sha = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
    route = respx.get(f"https://api.contrastcyber.com/v1/password/{sha}").mock(
        return_value=httpx.Response(200, json={"pwned": True})
    )
    with ContrastAPI() as client:
        client.password.check(sha)
    assert route.called


@respx.mock
def test_username_lookup_url():
    route = respx.get("https://api.contrastcyber.com/v1/username/octocat").mock(
        return_value=httpx.Response(200, json={"platforms": []})
    )
    with ContrastAPI() as client:
        client.username.lookup("octocat")
    assert route.called


# ---------------------------------------------------------------------------
# Code-security checks
# ---------------------------------------------------------------------------


@respx.mock
def test_check_secrets_post_body_with_language():
    route = respx.post("https://api.contrastcyber.com/v1/check/secrets").mock(
        return_value=httpx.Response(200, json={"findings": []})
    )
    with ContrastAPI() as client:
        client.check.secrets("API_KEY = 'sk-test'", "python")
    body = route.calls.last.request.read()
    assert b"code" in body and b"language" in body and b"python" in body


@respx.mock
def test_check_secrets_omits_language_when_none():
    route = respx.post("https://api.contrastcyber.com/v1/check/secrets").mock(
        return_value=httpx.Response(200, json={"findings": []})
    )
    with ContrastAPI() as client:
        client.check.secrets("API_KEY = 'sk-test'")
    body = route.calls.last.request.read()
    assert b"language" not in body


@respx.mock
def test_check_injection_post_body():
    route = respx.post("https://api.contrastcyber.com/v1/check/injection").mock(
        return_value=httpx.Response(200, json={"findings": []})
    )
    with ContrastAPI() as client:
        client.check.injection("query = 'SELECT * FROM u WHERE id=' + uid", "python")
    assert route.called


@respx.mock
def test_check_headers_post_body():
    route = respx.post("https://api.contrastcyber.com/v1/check/headers").mock(
        return_value=httpx.Response(200, json={"score": 80})
    )
    with ContrastAPI() as client:
        client.check.headers({"Strict-Transport-Security": "max-age=31536000"})
    body = route.calls.last.request.read()
    assert b"headers" in body


def test_check_headers_validation():
    with ContrastAPI() as client, pytest.raises(ValueError, match="dict"):
        client.check.headers("Strict-Transport-Security: max-age=31536000")  # type: ignore[arg-type]


@respx.mock
def test_check_dependencies_post_body():
    route = respx.post("https://api.contrastcyber.com/v1/check/dependencies").mock(
        return_value=httpx.Response(200, json={"vulnerabilities": []})
    )
    with ContrastAPI() as client:
        client.check.dependencies(["lodash@4.17.20", "django==2.0"])
    body = route.calls.last.request.read()
    assert b"packages" in body and b"lodash" in body


def test_check_dependencies_validation():
    with ContrastAPI() as client, pytest.raises(ValueError, match="packages"):
        client.check.dependencies("lodash@4.17.20")  # type: ignore[arg-type]


@respx.mock
def test_scan_headers_url():
    route = respx.get("https://api.contrastcyber.com/v1/scan/headers/example.com").mock(
        return_value=httpx.Response(200, json={"score": 75})
    )
    with ContrastAPI() as client:
        client.scan.headers("example.com")
    assert route.called
