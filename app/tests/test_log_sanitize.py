"""Tests for _sanitize_path (app/main.py) — PII redaction for log output."""

import pytest
from main import _sanitize_path


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
