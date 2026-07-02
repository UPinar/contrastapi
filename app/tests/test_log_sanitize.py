"""Tests for _sanitize_path (app/core/metrics.py) — PII redaction for log output."""

import pytest
from core.metrics import _sanitize_path


@pytest.mark.parametrize(
    "path, expected",
    [
        # Sub-action preservation
        ("/v1/cve/lookup/CVE-2024-3094", "/v1/cve/lookup/***"),
        ("/v1/cve/search/apache", "/v1/cve/search/***"),
        ("/v1/threat/report/ioc123", "/v1/threat/report/***"),
        ("/v1/domain/bulk/items", "/v1/domain/bulk/***"),
        # No sub-action
        ("/v1/domain/example.com", "/v1/domain/***"),
        ("/v1/ip/8.8.8.8", "/v1/ip/***"),
        ("/v1/phone/+15551234567", "/v1/phone/***"),
        ("/v1/email/disposable/test@example.com", "/v1/email/disposable/***"),
        ("/v1/email/mx/example.com", "/v1/email/mx/***"),
        ("/v1/scan/headers/example.com", "/v1/scan/headers/***"),
        ("/v1/username/johndoe", "/v1/username/***"),
        ("/v1/archive/example.com", "/v1/archive/***"),
        ("/v1/scan/example.com", "/v1/scan/***"),
        ("/v1/redirect/https://bit.ly/3xyz", "/v1/redirect/***"),
        ("/v1/robots/example.com", "/v1/robots/***"),
        ("/v1/brand/example.com", "/v1/brand/***"),
        ("/v1/seo/example.com", "/v1/seo/***"),
        ("/v1/audit/example.com", "/v1/audit/***"),
        ("/v1/email/verify/user@example.com", "/v1/email/verify/***"),
        ("/v1/email/security-posture/example.com", "/v1/email/security-posture/***"),
        ("/v1/threat-report/8.8.8.8", "/v1/threat-report/***"),
        ("/v1/kev/CVE-2024-3094", "/v1/kev/***"),
        ("/v1/atlas/AML.T0051", "/v1/atlas/***"),
        ("/v1/atlas/case-studies/AML.CS0021", "/v1/atlas/case-studies/***"),
        ("/v1/d3fend/D3-NTA", "/v1/d3fend/***"),
        ("/v1/d3fend/attack/T1059", "/v1/d3fend/attack/***"),
        ("/v1/sigma/proc_creation_win_susp_calc", "/v1/sigma/***"),
        ("/v1/cwe/CWE-79", "/v1/cwe/***"),
        # Case-insensitive bypass prevention
        ("/V1/CVE/LOOKUP/CVE-2024-3094", "/v1/cve/lookup/***"),
        ("/V1/DOMAIN/Example.COM", "/v1/domain/***"),
        ("/v1/Ip/8.8.8.8", "/v1/ip/***"),
        # Query strings dropped (may contain PII — emails, callbacks, secrets)
        ("/v1/cve/lookup/CVE-2024?format=json", "/v1/cve/lookup/***"),
        ("/v1/domain/example.com?secret=user@example.com", "/v1/domain/***"),
        # Multi-segment paths (defense in depth — redact everything after category)
        ("/v1/ioc/deep/nested/1.2.3.4", "/v1/ioc/***"),
        ("/v1/domain/a/b/c", "/v1/domain/***"),
        # Control character stripping
        ("/v1/domain/ex\tample.com", "/v1/domain/***"),
        ("/v1/ip/\x00\x011.1.1.1", "/v1/ip/***"),
        # No match — paths outside /v1 whitelist
        ("/v1/health", "/v1/health"),
        ("/v1/capabilities", "/v1/capabilities"),
        ("/v2/cve/lookup/CVE-XXX", "/v2/cve/lookup/CVE-XXX"),
        ("/", "/"),
        ("", ""),
    ],
)
def test_sanitize_path(path, expected):
    assert _sanitize_path(path) == expected
