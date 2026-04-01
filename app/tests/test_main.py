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
    assert r.status_code == 200


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
