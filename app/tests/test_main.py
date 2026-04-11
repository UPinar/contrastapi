"""Tests for main.py — app endpoints"""

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


# --- Landing page ---


def test_landing_page_200():
    r = client.get("/")
    assert r.status_code == 200
    assert "ContrastAPI" in r.text


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
    for src in data["data_sources"].values():
        assert "last_sync" not in src
        assert "records" not in src


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
    assert "detail" in data or "error" in data


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
    r = client.get("/v1/cves/recent?hours=1&limit=1")
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


def test_threat_report_cost_exhausts_free_limit_at_25():
    """24 threat-report calls = 96 credits (ok), 25th = 100 (ok), 26th = 104 > 100 (429).

    Uses X-Forwarded-For to get a non-localhost IP so rate limiting actually enforces.
    Hits an invalid IP so authenticate() runs but the handler exits fast with 400.
    """
    from ratelimit import reset

    reset("api")
    headers = {"X-Forwarded-For": "203.0.113.42"}
    for i in range(25):
        r = client.get("/v1/threat-report/not_an_ip", headers=headers)
        assert r.status_code == 400, f"call {i + 1} expected 400, got {r.status_code}"
    # 26th call exceeds limit
    r = client.get("/v1/threat-report/not_an_ip", headers=headers)
    assert r.status_code == 429
    reset("api")


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
