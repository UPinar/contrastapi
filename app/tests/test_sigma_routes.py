"""Integration tests for /v1/sigma/* REST endpoints."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from main import app
from sigma import get_sigma_index

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "sigma"


@pytest.fixture(autouse=True)
def _load_fixtures_into_index():
    """Reset and populate the global SigmaRuleIndex with the 4 Batch A fixtures."""
    idx = get_sigma_index()
    idx.rules.clear()
    idx.technique_index.clear()
    idx.cve_index.clear()
    idx.product_index.clear()
    idx.category_index.clear()
    idx.load_from_directory(FIXTURE_DIR, exclude_deprecated=False)
    yield
    idx.rules.clear()
    idx.technique_index.clear()
    idx.cve_index.clear()
    idx.product_index.clear()
    idx.category_index.clear()


client = TestClient(app)


# --- GET /v1/sigma/{rule_id} ---


def test_sigma_lookup_by_id_found():
    """T1059 fixture rule_id round-trip."""
    r = client.get("/v1/sigma/195e1b9d-bfc2-4ffa-ab4e-35aef69815f8")
    assert r.status_code == 200
    data = r.json()
    assert data["rule"]["rule_id"] == "195e1b9d-bfc2-4ffa-ab4e-35aef69815f8"
    assert data["rule"]["title"] == "Suspicious Process Creation - Powershell"
    assert data["rule"]["status"] == "stable"


def test_sigma_lookup_by_id_not_found():
    """Unknown UUID returns 404 with structured error envelope."""
    r = client.get("/v1/sigma/00000000-0000-0000-0000-000000000000")
    assert r.status_code == 404
    body = r.json()
    assert body["error"]["code"] == "not_found"


def test_sigma_lookup_by_id_invalid_format():
    """Non-UUID rule_id returns 422 (Pydantic Path validator)."""
    r = client.get("/v1/sigma/not-a-uuid")
    assert r.status_code == 422


# --- GET /v1/sigma/search ---


def test_sigma_search_by_technique():
    """T1059 prefix-match returns the powershell fixture."""
    r = client.get("/v1/sigma/search?technique=T1059")
    assert r.status_code == 200
    data = r.json()
    assert data["total_matches"] >= 1
    titles = [rule["title"] for rule in data["rules"]]
    assert "Suspicious Process Creation - Powershell" in titles


def test_sigma_search_by_cve():
    """CVE-2024-1234 matches the AWS fixture (cve.2024-1234 normalized)."""
    r = client.get("/v1/sigma/search?cve_id=CVE-2024-1234")
    assert r.status_code == 200
    data = r.json()
    assert data["total_matches"] == 1


def test_sigma_search_by_logsource_product():
    """logsource_product=windows returns the powershell fixture."""
    r = client.get("/v1/sigma/search?logsource_product=windows")
    assert r.status_code == 200
    data = r.json()
    assert data["total_matches"] >= 1


def test_sigma_search_by_query_freetext():
    """Substring match on title/description."""
    r = client.get("/v1/sigma/search?query=powershell")
    assert r.status_code == 200
    data = r.json()
    assert data["total_matches"] >= 1


def test_sigma_search_filter_by_status():
    """status=stable filters out non-stable rules."""
    r = client.get("/v1/sigma/search?logsource_product=windows&status=stable")
    assert r.status_code == 200
    data = r.json()
    for rule in data["rules"]:
        assert rule["status"] == "stable"


def test_sigma_search_filter_by_level():
    """level=high returns high+critical only."""
    r = client.get("/v1/sigma/search?query=powershell&level=high")
    assert r.status_code == 200
    data = r.json()
    for rule in data["rules"]:
        assert rule["level"] in {"high", "critical"}


def test_sigma_search_excludes_deprecated_by_default():
    """Deprecated rules excluded unless include_deprecated=true."""
    r = client.get("/v1/sigma/search?query=deprecated")
    data = r.json()
    for rule in data["rules"]:
        assert rule["status"] != "deprecated"


def test_sigma_search_pagination_limit():
    """limit parameter capped at 200 — over-cap rejected with 422."""
    r = client.get("/v1/sigma/search?query=a&limit=500")
    assert r.status_code == 422
    r2 = client.get("/v1/sigma/search?query=a&limit=200")
    assert r2.status_code == 200
    assert r2.json()["limit"] == 200


def test_sigma_search_pagination_offset():
    """offset skips initial results."""
    r = client.get("/v1/sigma/search?query=a&limit=1&offset=0")
    r2 = client.get("/v1/sigma/search?query=a&limit=1&offset=1")
    assert r.status_code == 200 and r2.status_code == 200


def test_sigma_search_no_filters_returns_all():
    """Empty query returns all non-deprecated rules."""
    r = client.get("/v1/sigma/search")
    assert r.status_code == 200
    data = r.json()
    assert data["total_matches"] >= 3


def test_sigma_search_next_calls_atlas_pivot():
    """A rule with attack.t#### tag surfaces atlas_technique_lookup pivot."""
    r = client.get("/v1/sigma/search?technique=T1059")
    data = r.json()
    assert data["rules"], "expected at least one match"
    next_calls = data.get("next_calls", []) or []
    if next_calls:
        tools = {hint["tool"] for hint in next_calls}
        assert "atlas_technique_lookup" in tools


# --- POST /v1/sigma/bulk ---


def test_sigma_bulk_mixed_ok_and_not_found():
    """3 UUIDs: 2 known + 1 unknown returns 3 items."""
    r = client.post(
        "/v1/sigma/bulk",
        json={
            "rule_ids": [
                "195e1b9d-bfc2-4ffa-ab4e-35aef69815f8",
                "abcd1234-5678-90ab-cdef-1234567890ab",
                "00000000-0000-0000-0000-000000000000",
            ]
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert data["total"] == 3
    statuses = {item["status"] for item in data["results"]}
    assert "ok" in statuses
    assert "not_found" in statuses


def test_sigma_bulk_too_many():
    """>50 rule_ids returns 422."""
    r = client.post(
        "/v1/sigma/bulk",
        json={"rule_ids": ["00000000-0000-0000-0000-000000000000"] * 51},
    )
    assert r.status_code == 422


def test_sigma_bulk_empty():
    """Empty rule_ids returns 422."""
    r = client.post("/v1/sigma/bulk", json={"rule_ids": []})
    assert r.status_code == 422


def test_sigma_bulk_invalid_uuid_format():
    """Item with invalid UUID format flagged status=invalid_format."""
    r = client.post(
        "/v1/sigma/bulk",
        json={"rule_ids": ["not-a-uuid", "195e1b9d-bfc2-4ffa-ab4e-35aef69815f8"]},
    )
    assert r.status_code == 200
    data = r.json()
    formats = {item["status"] for item in data["results"]}
    assert "invalid_format" in formats


def test_sigma_bulk_summary_string():
    """summary echoes count: 'N/M rules found'."""
    r = client.post(
        "/v1/sigma/bulk",
        json={
            "rule_ids": [
                "195e1b9d-bfc2-4ffa-ab4e-35aef69815f8",
                "00000000-0000-0000-0000-000000000000",
            ]
        },
    )
    data = r.json()
    assert "rules found" in data["summary"]
