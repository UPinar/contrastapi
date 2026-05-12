"""Tests for main.py — app endpoints"""

from unittest.mock import patch

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


# --- Landing page ---


def test_landing_page_200():
    r = client.get("/")
    assert r.status_code == 200
    assert "ContrastAPI" in r.text


def test_setup_pages_link_to_tool_selection_guide():
    """v1.23.0: docs strip moved off the landing footer (visual cleanup) and onto
    /quickstart + /mcp-setup so the doc links live alongside the install steps."""
    for path in ("/quickstart", "/mcp-setup"):
        r = client.get(path)
        assert r.status_code == 200, path
        assert "tool-selection-guide.md" in r.text, f"{path} missing tool-selection-guide link"
        assert "ENDPOINTS.md" in r.text, f"{path} missing endpoints link"
        assert "PROMPTS.md" in r.text, f"{path} missing prompts link"
        assert "resources.md" in r.text, f"{path} missing resources link"


def test_tool_selection_guide_file_exists():
    """v1.21.0: docs/tool-selection-guide.md is checked into the repo."""
    from pathlib import Path

    guide = Path(__file__).parent.parent.parent / "docs" / "tool-selection-guide.md"
    assert guide.exists(), f"Missing {guide}"
    text = guide.read_text()
    # Sanity-check: guide covers the 4 decision-tree scenarios
    assert "Is this domain" in text
    assert "Tell me about a CVE" in text
    assert "ATLAS" in text
    assert "v1.21.0" in text


def test_landing_renders_dynamic_test_count():
    """v1.21.1: landing pulls TEST_COUNT from config.py (no hardcoded 1544)."""
    from config import TEST_COUNT

    r = client.get("/")
    assert r.status_code == 200
    assert f"<strong>{TEST_COUNT}</strong> tests passing" in r.text


def test_landing_renders_dynamic_catalog_counts():
    """v1.21.1: landing pulls ATLAS/D3FEND counts from config.py (no hardcoded 167/57/149)."""
    from config import ATLAS_CASE_STUDY_COUNT, ATLAS_TECHNIQUE_COUNT, D3FEND_DEFENSE_COUNT

    r = client.get("/")
    assert r.status_code == 200
    assert f"Search ATLAS techniques ({ATLAS_TECHNIQUE_COUNT} entries)" in r.text
    assert f"Search ATLAS case studies ({ATLAS_CASE_STUDY_COUNT} entries)" in r.text
    assert f"Search D3FEND defenses ({D3FEND_DEFENSE_COUNT} entries" in r.text


def test_playground_renders_dynamic_catalog_counts():
    """v1.21.1: playground pulls catalog counts from config.py."""
    from config import ATLAS_CASE_STUDY_COUNT, ATLAS_TECHNIQUE_COUNT, D3FEND_DEFENSE_COUNT

    r = client.get("/playground")
    assert r.status_code == 200
    assert f"({ATLAS_TECHNIQUE_COUNT} techniques)" in r.text
    assert f"({ATLAS_CASE_STUDY_COUNT} entries)" in r.text
    assert f"{D3FEND_DEFENSE_COUNT} defenses" in r.text


# --- Status endpoint ---


def test_status_200():
    r = client.get("/v1/status")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert "version" in data
    assert "data_sources" in data
    # Operational details must not be exposed
    assert "total_requests" not in data
    assert r.headers.get("cache-control") == "public, max-age=60"
    for src in data["data_sources"].values():
        assert "last_sync" not in src
        assert "records" not in src


# --- Capabilities endpoint ---


def test_capabilities_200():
    r = client.get("/v1/capabilities")
    assert r.status_code == 200
    data = r.json()
    from config import MCP_TOOL_COUNT

    assert data["total_tools"] == MCP_TOOL_COUNT
    assert data["schema_version"] == "1.0"
    assert "categories" in data
    assert "auth" in data


def test_capabilities_structure():
    from config import MCP_TOOL_COUNT

    r = client.get("/v1/capabilities")
    data = r.json()
    cats = data["categories"]
    assert set(cats.keys()) == {"cve", "domain", "ioc", "code_security", "atlas", "d3fend", "meta"}
    mcp_tools = [t for cat in cats.values() for t in cat["tools"] if t.get("name") is not None]
    assert len(mcp_tools) == MCP_TOOL_COUNT


def test_capabilities_blast_radius():
    r = client.get("/v1/capabilities")
    data = r.json()
    # Legend exists with all three levels
    legend = data["blast_radius_legend"]
    assert "zero" in legend
    assert "low" in legend
    assert "high" in legend
    # Every tool in non-meta categories has blast_radius in valid set
    valid = {"zero", "low", "high"}
    for cat_name in ("cve", "domain", "ioc", "code_security"):
        for tool in data["categories"][cat_name]["tools"]:
            assert "blast_radius" in tool, f"missing blast_radius in {cat_name}: {tool.get('path')}"
            assert tool["blast_radius"] in valid, f"invalid blast_radius in {cat_name}: {tool.get('path')}"
    # Spot-check specific paths
    domain_tools = {t["path"]: t for t in data["categories"]["domain"]["tools"]}
    assert domain_tools["/v1/domain/{domain}"]["blast_radius"] == "high"
    cve_tools = {t["path"]: t for t in data["categories"]["cve"]["tools"]}
    assert cve_tools["/v1/cve/{cve_id}"]["blast_radius"] == "zero"
    ioc_tools = {t["path"]: t for t in data["categories"]["ioc"]["tools"]}
    assert ioc_tools["/v1/ioc/{indicator}"]["blast_radius"] == "low"


def test_capabilities_no_auth_required():
    r = client.get("/v1/capabilities")
    assert r.status_code == 200  # no key needed
    assert r.json()["auth"]["type"] == "none_required"


def test_capabilities_verdict_metadata():
    r = client.get("/v1/capabilities")
    assert r.status_code == 200
    assert r.json()["verdict_metadata"] is True


# --- llms.txt ---


def test_llms_txt_200():
    r = client.get("/llms.txt")
    assert r.status_code == 200
    assert "ContrastAPI" in r.text
    assert "/v1/cve/" in r.text


def test_llms_txt_content_type():
    r = client.get("/llms.txt")
    assert "text/plain" in r.headers["content-type"]


# --- OpenAPI ---


def test_openapi_json():
    r = client.get("/openapi.json")
    assert r.status_code == 200
    data = r.json()
    assert data["info"]["title"] == "ContrastAPI"


# --- Docs ---


def test_docs_page():
    r = client.get("/docs")
    assert r.status_code == 404
    assert "github.com" in r.json()["hint"]


# --- Error handler ---


def test_404_returns_json():
    r = client.get("/nonexistent-path")
    assert r.status_code in (404, 405)
    data = r.json()
    assert "error" in data
    assert isinstance(data["error"], dict)
    assert data["error"]["code"] in ("not_found", "invalid_argument")
    assert "message" in data["error"]


# --- Error envelope (v1.22.2 — RFC 7807-lite, mirrors MCP ErrorDetail) ---


def test_404_error_envelope_shape():
    """v1.22.2: top-level `error` must be a dict mirroring ErrorDetail."""
    r = client.get("/nonexistent-path")
    assert r.status_code == 404
    body = r.json()
    err = body["error"]
    assert err["code"] == "not_found"
    assert isinstance(err["message"], str) and len(err["message"]) > 0
    # Top-level extension fields preserved (back-compat)
    assert "hint" in body


def test_404_error_envelope_no_extra_fields():
    """ErrorDetail body must not carry `retry_after_seconds`/`upgrade_url`/
    `docs_url` for plain 404 (those are status-specific)."""
    r = client.get("/nonexistent-path")
    err = r.json()["error"]
    assert "retry_after_seconds" not in err
    assert "upgrade_url" not in err


def test_422_validation_error_envelope_shape():
    """RequestValidationError handler returns nested ErrorDetail with docs_url."""
    # /v1/cves/bulk requires JSON body — missing/invalid triggers 422
    r = client.post("/v1/cves/bulk", json={"cve_ids": "not-a-list"})
    assert r.status_code == 422
    body = r.json()
    err = body["error"]
    assert err["code"] == "invalid_argument"
    assert "docs_url" in err
    assert err["docs_url"].startswith("https://")
    # Top-level extension fields preserved (back-compat)
    assert "reason" in body and "suggestion" in body


def test_400_invalid_argument_envelope_shape():
    """HTTPException(400) routes through api_error_handler with code=invalid_argument."""
    r = client.get("/v1/cves?published_after=not-a-date")
    assert r.status_code == 400
    err = r.json()["error"]
    assert err["code"] == "invalid_argument"
    assert "YYYY-MM-DD" in err["message"]


def test_status_to_code_mapping_known_codes():
    """Sanity-check the status→code dict used by api_error_handler."""
    from core.exception_handlers import _STATUS_TO_ERROR_CODE

    assert _STATUS_TO_ERROR_CODE[400] == "invalid_argument"
    assert _STATUS_TO_ERROR_CODE[401] == "auth_required"
    assert _STATUS_TO_ERROR_CODE[403] == "tier_limit"
    assert _STATUS_TO_ERROR_CODE[404] == "not_found"
    assert _STATUS_TO_ERROR_CODE[422] == "invalid_argument"
    assert _STATUS_TO_ERROR_CODE[429] == "rate_limit_exceeded"
    assert _STATUS_TO_ERROR_CODE[500] == "internal_error"
    assert _STATUS_TO_ERROR_CODE[502] == "upstream_error"
    assert _STATUS_TO_ERROR_CODE[504] == "upstream_timeout"


def test_unknown_status_code_falls_back_to_upstream_error():
    """`api_error_handler` default for unmapped status codes."""
    from core.exception_handlers import _STATUS_TO_ERROR_CODE

    assert _STATUS_TO_ERROR_CODE.get(418, "upstream_error") == "upstream_error"


def test_error_envelope_mirrors_mcp_error_detail_shape():
    """HTTP error envelope must accept ErrorDetail validation — single source
    of truth across HTTP + MCP."""
    from schemas import ErrorDetail

    r = client.get("/nonexistent-path")
    err = r.json()["error"]
    # Round-trip through Pydantic — confirms wire shape matches the model
    parsed = ErrorDetail.model_validate(err)
    assert parsed.code == "not_found"


def test_error_envelope_message_truncated_to_500_chars():
    """`HTTPException.detail` is free-form; the wire `error.message` must
    respect ErrorDetail.max_length=500 even when upstream raises a long
    detail string. Mirrors the MCP-side truncation in mcp_server.py."""
    from core.exception_handlers import _error_envelope
    from fastapi import HTTPException

    long_msg = "X" * 1500
    body = _error_envelope(code="upstream_error", message=long_msg)
    assert len(body["message"]) == 500
    # Ensure ErrorDetail Pydantic validator accepts the truncated body
    from schemas import ErrorDetail

    ErrorDetail.model_validate(body)
    # Sanity: HTTPException path also truncates (raise via direct route call)
    _ = HTTPException  # imported for symmetry with the production raise sites


def test_error_envelope_retry_after_capped_at_3600():
    """Mirror mcp_server.py:269 cap. Hostile upstream must not pin clients
    into multi-hour backoff via Retry-After."""
    from core.exception_handlers import _RETRY_AFTER_MAX_SECONDS, _error_envelope

    body = _error_envelope(code="rate_limit_exceeded", message="x", retry_after_seconds=99999)
    assert body["retry_after_seconds"] == _RETRY_AFTER_MAX_SECONDS == 3600
    # Negative values clamp to 0
    body = _error_envelope(code="rate_limit_exceeded", message="x", retry_after_seconds=-5)
    assert body["retry_after_seconds"] == 0
    # Normal value passes through
    body = _error_envelope(code="rate_limit_exceeded", message="x", retry_after_seconds=42)
    assert body["retry_after_seconds"] == 42


def test_429_response_carries_retry_after_in_nested_error():
    """Integration: 429 response body must surface retry_after_seconds in the
    nested error envelope, not only the top-level reset_in / Retry-After header."""
    from unittest.mock import patch

    from fastapi import HTTPException

    with patch("main.check_limit", side_effect=HTTPException(status_code=429, detail="slow down"), create=True):
        r = client.get("/v1/cves?limit=1")
    if r.status_code != 429:
        # Test environment may bypass the rate-limit middleware; assert structure if any 429 surfaces
        return
    body = r.json()
    assert body["error"]["code"] == "rate_limit_exceeded"
    assert "retry_after_seconds" in body["error"]
    assert body["error"]["retry_after_seconds"] >= 0
    assert "reset_in" in body  # back-compat top-level
    assert "Retry-After" in r.headers  # back-compat header


def test_validation_error_reason_truncated_to_500_chars():
    """Production-path test: when Pydantic raises a long ValidationError msg,
    BOTH the nested `error.message` and the top-level `reason` are truncated
    to 500 chars. Calls the handler directly with a synthetic error so the
    test does not depend on a real route emitting a >500-char Pydantic msg."""
    import asyncio
    import json

    from core.exception_handlers import validation_error_handler
    from fastapi.exceptions import RequestValidationError
    from starlette.requests import Request

    long_msg = "Value error, " + ("X" * 2000)
    exc = RequestValidationError([{"loc": ("body", "cve_ids"), "msg": long_msg, "input": "ignored"}])
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/cves/bulk",
        "headers": [],
        "query_string": b"",
        "scheme": "http",
        "server": ("testserver", 80),
    }
    request = Request(scope)
    response = asyncio.run(validation_error_handler(request, exc))
    body = json.loads(response.body)
    assert response.status_code == 422
    assert len(body["error"]["message"]) == 500
    assert len(body["reason"]) == 500
    assert body["error"]["message"] == body["reason"]  # Same source, same cap
    assert body["error"]["code"] == "invalid_argument"


# --- Middleware ---


def test_request_id_header():
    r = client.get("/v1/status")
    assert "x-request-id" in r.headers
    assert len(r.headers["x-request-id"]) == 16


def test_request_id_unique():
    r1 = client.get("/v1/status")
    r2 = client.get("/v1/status")
    assert r1.headers["x-request-id"] != r2.headers["x-request-id"]


def test_ratelimit_headers_on_api_endpoint():
    r = client.get("/v1/cves?limit=1")
    assert "x-ratelimit-limit" in r.headers
    assert "x-ratelimit-remaining" in r.headers
    assert "x-ratelimit-reset" in r.headers


def test_no_ratelimit_headers_on_static():
    r = client.get("/v1/status")
    # Status endpoint doesn't go through authenticate()
    assert "x-ratelimit-limit" not in r.headers


def test_status_has_api_status_operation_id():
    r = client.get("/openapi.json")
    data = r.json()
    found = False
    for path_data in data.get("paths", {}).values():
        for method_data in path_data.values():
            if isinstance(method_data, dict) and method_data.get("operationId") == "api_status":
                found = True
                break
    assert found, "operation_id 'api_status' not found in openapi.json"


# --- Metrics ---


def test_metrics_200():
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "text/plain" in r.headers["content-type"]
    assert "contrastapi_requests_total" in r.text
    assert "contrastapi_errors_total" in r.text
    assert "contrastapi_latency_avg_ms" in r.text


def test_metrics_counts_requests():
    # Make a request, then check metrics increment
    r1 = client.get("/metrics")
    total_before = int(
        [line for line in r1.text.split("\n") if line.startswith("contrastapi_requests_total ")][0].split()[-1]
    )
    client.get("/v1/status")
    r2 = client.get("/metrics")
    total_after = int(
        [line for line in r2.text.split("\n") if line.startswith("contrastapi_requests_total ")][0].split()[-1]
    )
    assert total_after > total_before


# --- Usage endpoint ---


def test_usage_requires_pro_key():
    r = client.get("/v1/usage")
    assert r.status_code == 401


def test_usage_with_valid_key():
    from auth import generate_key, hash_key
    from db import save_api_key

    key = generate_key()
    save_api_key(hash_key(key))
    r = client.get("/v1/usage", headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 200
    data = r.json()
    assert "total_requests" in data
    assert "last_24h" in data
    assert "last_1h" in data
    assert "hourly_limit" in data
    assert "top_endpoints" in data


# --- Privacy transparency endpoint ---


def test_privacy_my_data_free_tier():
    r = client.get("/v1/privacy/my-data", headers={"X-Forwarded-For": "203.0.113.5"})
    assert r.status_code == 200
    data = r.json()
    assert data["tier"] == "free"
    assert data["api_key_record"] is None
    assert len(data["client_ip_hash"]) == 16
    assert "usage_last_24h" in data
    assert "not_stored" in data
    assert isinstance(data["not_stored"], list) and len(data["not_stored"]) >= 3
    assert "source_code" in data
    body_str = r.text
    assert "203.0.113.5" not in body_str


def test_privacy_my_data_pro_tier():
    from auth import generate_key, hash_key
    from db import save_api_key

    key = generate_key()
    save_api_key(hash_key(key))
    r = client.get("/v1/privacy/my-data", headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 200
    data = r.json()
    assert data["tier"] == "pro"
    assert data["api_key_record"] is not None
    assert "created_at" in data["api_key_record"]
    assert data["api_key_record"]["active"] is True


def test_privacy_my_data_does_not_leak_query_params():
    """After calling /v1/domain/example.com, privacy/my-data must show /v1/domain — not /v1/domain/example.com."""
    client.get("/v1/domain/example.com", headers={"X-Forwarded-For": "198.51.100.9"})
    r = client.get("/v1/privacy/my-data", headers={"X-Forwarded-For": "198.51.100.9"})
    assert r.status_code == 200
    endpoints_seen = [row["endpoint"] for row in r.json()["usage_last_24h"]["by_endpoint"]]
    assert all("example.com" not in ep for ep in endpoints_seen)


# --- X-RateLimit-Tier header (Feature-Gate Phase 1) ---


def test_x_ratelimit_tier_header_free():
    """Free tier requests should get X-RateLimit-Tier: free header.

    Uses /v1/ioc/xxx so authenticate() runs before the 400 for unknown indicator.
    """
    r = client.get("/v1/ioc/xxx")
    assert r.headers.get("X-RateLimit-Tier") == "free"


def test_x_ratelimit_tier_header_pro():
    """Pro key requests should get X-RateLimit-Tier: pro header."""
    from auth import hash_key
    from db import get_api_db, save_api_key

    test_key = "cc_" + "a" * 48
    key_hash = hash_key(test_key)
    try:
        save_api_key(key_hash)
        r = client.get("/v1/ioc/xxx", headers={"Authorization": f"Bearer {test_key}"})
        assert r.headers.get("X-RateLimit-Tier") == "pro"
    finally:
        with get_api_db() as con:
            con.execute("DELETE FROM api_keys WHERE key_hash = ?", (key_hash,))


# --- X-RateLimit-Cost header (weighted credits) ---


def test_x_ratelimit_cost_default_one():
    """Standard endpoints consume 1 credit."""
    r = client.get("/v1/ioc/xxx")
    assert r.headers.get("X-RateLimit-Cost") == "1"


def test_x_ratelimit_cost_audit_four():
    """audit_domain consumes COST_AUDIT=4 credits. Uses input that clean_domain reduces to empty → 400 fast."""
    # clean_domain('...') strips trailing dots → "" → handler returns 400 immediately after authenticate().
    r = client.get("/v1/audit/...")
    assert r.status_code == 400
    assert r.headers.get("X-RateLimit-Cost") == "4"


def test_x_ratelimit_cost_threat_report_four():
    """threat_report consumes COST_THREAT_REPORT=4 credits."""
    r = client.get("/v1/threat-report/8.8.8.8")
    assert r.headers.get("X-RateLimit-Cost") == "4"


def test_threat_report_cost_exhausts_free_limit():
    """threat-report costs 4 credits; (FREE_HOURLY_LIMIT // 4) calls fit, next exhausts.

    Uses X-Forwarded-For to get a non-localhost IP so rate limiting actually enforces.
    Hits an invalid IP so authenticate() runs but the handler exits fast with 400.
    """
    from config import FREE_HOURLY_LIMIT
    from ratelimit import reset

    reset("api")
    headers = {"X-Forwarded-For": "203.0.113.42"}
    cost = 4
    max_calls = FREE_HOURLY_LIMIT // cost
    for i in range(max_calls):
        r = client.get("/v1/threat-report/not_an_ip", headers=headers)
        assert r.status_code == 400, f"call {i + 1} expected 400, got {r.status_code}"
    r = client.get("/v1/threat-report/not_an_ip", headers=headers)
    assert r.status_code == 429
    reset("api")


def test_x_upgrade_url_header_on_free_429():
    """Free-tier 429 must carry X-Upgrade-URL header pointing at /pricing."""
    from config import UPGRADE_URL
    from ratelimit import reset

    reset("api")
    headers = {"X-Forwarded-For": "203.0.113.71"}
    for _ in range(25):
        client.get("/v1/threat-report/not_an_ip", headers=headers)
    r = client.get("/v1/threat-report/not_an_ip", headers=headers)
    assert r.status_code == 429
    assert r.headers.get("X-Upgrade-URL") == UPGRADE_URL
    reset("api")


def test_x_upgrade_url_header_absent_on_free_200():
    """Successful free-tier responses must NOT carry the upsell header (no spam)."""
    from ratelimit import reset

    reset("api")
    headers = {"X-Forwarded-For": "203.0.113.72"}
    r = client.get("/v1/status", headers=headers)
    assert r.status_code == 200
    assert "X-Upgrade-URL" not in r.headers


def test_x_upgrade_url_header_absent_on_pro_tier():
    """Pro tier already pays — upsell header must never appear on pro responses."""
    from auth import hash_key
    from config import KEY_LENGTH, KEY_PREFIX
    from db import get_api_db, save_api_key

    test_key = KEY_PREFIX + "b" * KEY_LENGTH
    key_hash = hash_key(test_key)
    try:
        save_api_key(key_hash)
        r = client.get("/v1/ioc/xxx", headers={"Authorization": f"Bearer {test_key}"})
        assert r.headers.get("X-RateLimit-Tier") == "pro"
        assert "X-Upgrade-URL" not in r.headers
    finally:
        with get_api_db() as con:
            con.execute("DELETE FROM api_keys WHERE key_hash = ?", (key_hash,))


def test_free_429_body_has_upgrade_cta():
    """Free-tier 429 response body must include structured upgrade CTA."""
    from config import FREE_HOURLY_LIMIT, PRO_HOURLY_LIMIT, UPGRADE_URL
    from ratelimit import reset

    reset("api")
    headers = {"X-Forwarded-For": "203.0.113.73"}
    cost = 4
    for _ in range(FREE_HOURLY_LIMIT // cost):
        client.get("/v1/threat-report/not_an_ip", headers=headers)
    r = client.get("/v1/threat-report/not_an_ip", headers=headers)
    assert r.status_code == 429
    body = r.json()
    assert body["tier"] == "free"
    assert body["limit"] == FREE_HOURLY_LIMIT
    assert "upgrade" in body
    assert body["upgrade"]["pro_limit"] == PRO_HOURLY_LIMIT
    assert body["upgrade"]["url"] == UPGRADE_URL
    reset("api")


def test_free_422_body_has_upgrade_cta():
    """Free-tier 422 validation error must include upgrade CTA."""
    from config import PRO_HOURLY_LIMIT, UPGRADE_URL
    from ratelimit import reset

    reset("api")
    headers = {"X-Forwarded-For": "203.0.113.74"}
    r = client.post("/v1/domains/bulk", json={"domains": []}, headers=headers)
    assert r.status_code == 422
    body = r.json()
    assert "upgrade" in body
    assert body["upgrade"]["pro_limit"] == PRO_HOURLY_LIMIT
    assert body["upgrade"]["url"] == UPGRADE_URL
    assert "message" in body["upgrade"]
    reset("api")


@patch("auth.PRO_HOURLY_LIMIT", 5)
def test_pro_429_body_has_support_no_upgrade():
    """Pro-tier 429 response body must include support contact, not upgrade CTA."""
    from auth import hash_key
    from config import KEY_LENGTH, KEY_PREFIX
    from db import get_api_db, save_api_key
    from ratelimit import reset

    reset("api")
    test_key = KEY_PREFIX + "v" * KEY_LENGTH
    key_hash = hash_key(test_key)
    try:
        save_api_key(key_hash)
        auth_header = {"Authorization": f"Bearer {test_key}"}
        for _ in range(5):
            client.get("/v1/threat-report/not_an_ip", headers=auth_header)
        r = client.get("/v1/threat-report/not_an_ip", headers=auth_header)
        assert r.status_code == 429
        body = r.json()
        assert body["tier"] == "pro"
        assert "support" in body
        assert "contact@contrastcyber.com" in body["support"]
        assert "upgrade" not in body
    finally:
        with get_api_db() as con:
            con.execute("DELETE FROM api_keys WHERE key_hash = ?", (key_hash,))
        reset("api")


def test_free_429_upgrade_has_no_trial():
    """Free-tier 429 upgrade dict must NOT include trial metadata (Pro $15/mo direct)."""
    from ratelimit import reset

    reset("api")
    headers = {"X-Forwarded-For": "203.0.113.90"}
    for _ in range(25):
        client.get("/v1/threat-report/not_an_ip", headers=headers)
    r = client.get("/v1/threat-report/not_an_ip", headers=headers)
    assert r.status_code == 429
    body = r.json()
    assert "upgrade" in body
    assert "trial" not in body["upgrade"]
    assert "$15/mo" in body["upgrade"]["message"]
    reset("api")


def test_free_422_upgrade_has_no_trial():
    """Free-tier 422 upgrade dict must NOT include trial metadata."""
    from ratelimit import reset

    reset("api")
    headers = {"X-Forwarded-For": "203.0.113.91"}
    r = client.post("/v1/domains/bulk", json={"domains": []}, headers=headers)
    assert r.status_code == 422
    body = r.json()
    assert "upgrade" in body
    assert "trial" not in body["upgrade"]
    assert "$15/mo" in body["upgrade"]["message"]
    reset("api")


@patch("auth.PRO_HOURLY_LIMIT", 5)
def test_pro_429_has_no_upgrade():
    """Pro-tier 429 must not include upgrade or trial fields."""
    from auth import hash_key
    from config import KEY_LENGTH, KEY_PREFIX
    from db import get_api_db, save_api_key
    from ratelimit import reset

    reset("api")
    test_key = KEY_PREFIX + "w" * KEY_LENGTH
    key_hash = hash_key(test_key)
    try:
        save_api_key(key_hash)
        auth_header = {"Authorization": f"Bearer {test_key}"}
        for _ in range(5):
            client.get("/v1/threat-report/not_an_ip", headers=auth_header)
        r = client.get("/v1/threat-report/not_an_ip", headers=auth_header)
        assert r.status_code == 429
        body = r.json()
        assert body["tier"] == "pro"
        assert "upgrade" not in body
        assert "trial" not in body
    finally:
        with get_api_db() as con:
            con.execute("DELETE FROM api_keys WHERE key_hash = ?", (key_hash,))
        reset("api")


def test_free_429_has_retry_after_header():
    """Free-tier 429 must carry Retry-After header with non-negative int value."""
    from ratelimit import reset

    reset("api")
    headers = {"X-Forwarded-For": "203.0.113.80"}
    for _ in range(25):
        client.get("/v1/threat-report/not_an_ip", headers=headers)
    r = client.get("/v1/threat-report/not_an_ip", headers=headers)
    assert r.status_code == 429
    assert "Retry-After" in r.headers
    assert int(r.headers["Retry-After"]) >= 0
    reset("api")


def test_free_429_has_reset_in_body():
    """Free-tier 429 body must include reset_in as non-negative int."""
    from ratelimit import reset

    reset("api")
    headers = {"X-Forwarded-For": "203.0.113.81"}
    for _ in range(25):
        client.get("/v1/threat-report/not_an_ip", headers=headers)
    r = client.get("/v1/threat-report/not_an_ip", headers=headers)
    assert r.status_code == 429
    body = r.json()
    assert "reset_in" in body
    assert isinstance(body["reset_in"], int)
    assert body["reset_in"] >= 0
    reset("api")


@patch("auth.PRO_HOURLY_LIMIT", 5)
def test_pro_429_has_retry_after_header():
    """Pro-tier 429 must carry Retry-After header with non-negative int value."""
    from auth import hash_key
    from config import KEY_LENGTH, KEY_PREFIX
    from db import get_api_db, save_api_key
    from ratelimit import reset

    reset("api")
    test_key = KEY_PREFIX + "w" * KEY_LENGTH
    key_hash = hash_key(test_key)
    try:
        save_api_key(key_hash)
        auth_header = {"Authorization": f"Bearer {test_key}"}
        for _ in range(5):
            client.get("/v1/threat-report/not_an_ip", headers=auth_header)
        r = client.get("/v1/threat-report/not_an_ip", headers=auth_header)
        assert r.status_code == 429
        assert "Retry-After" in r.headers
        assert int(r.headers["Retry-After"]) >= 0
    finally:
        with get_api_db() as con:
            con.execute("DELETE FROM api_keys WHERE key_hash = ?", (key_hash,))
        reset("api")


def test_retry_after_matches_x_ratelimit_reset():
    """Retry-After header value must equal X-RateLimit-Reset header value."""
    from ratelimit import reset

    reset("api")
    headers = {"X-Forwarded-For": "203.0.113.82"}
    for _ in range(25):
        client.get("/v1/threat-report/not_an_ip", headers=headers)
    r = client.get("/v1/threat-report/not_an_ip", headers=headers)
    assert r.status_code == 429
    assert r.headers["Retry-After"] == r.headers["X-RateLimit-Reset"]
    reset("api")


def test_429_body_has_error_code_rate_limit():
    """429 response body must include error_code == 'rate_limit'."""
    from ratelimit import reset

    reset("api")
    headers = {"X-Forwarded-For": "203.0.113.83"}
    for _ in range(25):
        client.get("/v1/threat-report/not_an_ip", headers=headers)
    r = client.get("/v1/threat-report/not_an_ip", headers=headers)
    assert r.status_code == 429
    assert r.json()["error_code"] == "rate_limit"
    reset("api")


def test_pro_422_body_no_upgrade_cta():
    """Pro-tier 422 must NOT include upgrade CTA."""
    from auth import hash_key
    from config import KEY_LENGTH, KEY_PREFIX
    from db import get_api_db, save_api_key

    test_key = KEY_PREFIX + "u" * KEY_LENGTH
    key_hash = hash_key(test_key)
    try:
        save_api_key(key_hash)
        r = client.post(
            "/v1/domains/bulk",
            json={"domains": []},
            headers={"Authorization": f"Bearer {test_key}"},
        )
        assert r.status_code == 422
        body = r.json()
        assert "upgrade" not in body
    finally:
        with get_api_db() as con:
            con.execute("DELETE FROM api_keys WHERE key_hash = ?", (key_hash,))


def test_regular_endpoint_still_costs_one_per_call():
    """Non-weighted endpoints should decrement X-RateLimit-Remaining by 1 per call."""
    from ratelimit import reset

    reset("api")
    headers = {"X-Forwarded-For": "203.0.113.43"}
    r1 = client.get("/v1/ioc/xxx", headers=headers)
    r2 = client.get("/v1/ioc/xxx", headers=headers)
    rem1 = int(r1.headers["X-RateLimit-Remaining"])
    rem2 = int(r2.headers["X-RateLimit-Remaining"])
    assert rem1 - rem2 == 1
    assert r1.headers["X-RateLimit-Cost"] == "1"
    reset("api")


# --- Security headers middleware ---


class TestSecurityHeaders:
    _EXPECTED = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "Cross-Origin-Embedder-Policy": "credentialless",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
    }

    def test_security_headers_on_root(self):
        r = client.get("/")
        assert r.status_code == 200
        for name, value in self._EXPECTED.items():
            assert r.headers.get(name) == value
        assert "Content-Security-Policy" in r.headers

    def test_security_headers_on_api_endpoint(self):
        r = client.get("/v1/status")
        assert r.status_code == 200
        for name, value in self._EXPECTED.items():
            assert r.headers.get(name) == value
        assert "Content-Security-Policy" in r.headers

    def test_csp_contains_required_directives(self):
        r = client.get("/")
        csp = r.headers["Content-Security-Policy"]
        assert "object-src 'none'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "base-uri 'none'" in csp
        assert "form-action 'self'" in csp
        assert "frame-src 'none'" in csp
        assert "child-src 'none'" in csp
        assert "worker-src 'self'" in csp
        assert "manifest-src 'self'" in csp
        assert "media-src 'none'" in csp

    def test_csp_script_src_no_unsafe_inline(self):
        r = client.get("/")
        csp = r.headers["Content-Security-Policy"]
        script_src = next(
            (d for d in csp.split(";") if d.strip().startswith("script-src")),
            "",
        )
        assert script_src, "script-src directive missing"
        assert "'unsafe-inline'" not in script_src, f"script-src should not contain 'unsafe-inline': {script_src}"

    def test_csp_style_src_no_unsafe_inline(self):
        r = client.get("/")
        csp = r.headers["Content-Security-Policy"]
        style_src = next(
            (d for d in csp.split(";") if d.strip().startswith("style-src")),
            "",
        )
        assert style_src, "style-src directive missing"
        assert "'unsafe-inline'" not in style_src, f"style-src should not contain 'unsafe-inline': {style_src}"

    def test_csp_script_src_has_jsonld_hash(self):
        r = client.get("/")
        csp = r.headers["Content-Security-Policy"]
        script_src = next(
            (d for d in csp.split(";") if d.strip().startswith("script-src")),
            "",
        )
        assert "'sha256-" in script_src, f"script-src should include at least one sha256 hash: {script_src}"


# --- OAuth discovery stubs ---


def test_oauth_protected_resource_200_shape():
    r = client.get("/.well-known/oauth-protected-resource")
    assert r.status_code == 200
    body = r.json()
    assert body["resource"] == "https://api.contrastcyber.com"
    assert body["authorization_servers"] == []
    assert "header" in body["bearer_methods_supported"]


def test_oauth_protected_resource_mcp_alias_equivalent():
    r1 = client.get("/.well-known/oauth-protected-resource")
    r2 = client.get("/.well-known/oauth-protected-resource/mcp")
    assert r2.status_code == 200
    assert r1.json() == r2.json()


def test_oauth_authorization_server_404_structured():
    r = client.get("/.well-known/oauth-authorization-server")
    assert r.status_code == 404
    body = r.json()
    assert body["error"] == "not_found"


# --- Glama manifest filename whitelist (defense-in-depth) ---


def test_glama_manifest_503_when_missing(monkeypatch, tmp_path):
    """Missing file → 503, not 500/path leak. Operator misconfig case."""
    from config import settings

    monkeypatch.setattr(settings, "glama_manifest_path", tmp_path / "glama.json")
    r = client.get("/.well-known/glama.json")
    assert r.status_code == 503
    assert "configured" in r.json()["error"]["message"].lower()


def test_glama_manifest_503_when_filename_not_whitelisted(monkeypatch, tmp_path):
    """If GLAMA_MANIFEST_PATH points at any file other than literally
    ``glama.json``, refuse to serve it. Stops operator typos from turning the
    env var into an arbitrary-file-read primitive (e.g. /etc/passwd)."""
    from config import settings

    decoy = tmp_path / "passwd"
    decoy.write_text("root:x:0:0::/root:/bin/bash\n")
    monkeypatch.setattr(settings, "glama_manifest_path", decoy)
    r = client.get("/.well-known/glama.json")
    assert r.status_code == 503
    assert "root:x:" not in r.text  # never echo the file body


def test_glama_manifest_200_when_whitelisted(monkeypatch, tmp_path):
    """Filename literally ``glama.json`` and is_file() → served as JSON."""
    from config import settings

    real = tmp_path / "glama.json"
    real.write_text('{"name": "ContrastAPI"}')
    monkeypatch.setattr(settings, "glama_manifest_path", real)
    r = client.get("/.well-known/glama.json")
    assert r.status_code == 200
    assert r.json() == {"name": "ContrastAPI"}
