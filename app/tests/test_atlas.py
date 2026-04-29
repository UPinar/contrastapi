"""Tests for MITRE ATLAS routes — atlas/routes.py."""

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def _seed_atlas():
    """Seed two techniques + one case study for routing tests."""
    from db import upsert_atlas_case_study, upsert_atlas_technique

    upsert_atlas_technique(
        "AML.T0000",
        name="Search Open Technical Databases",
        description="Adversaries may search publicly available research and technical documentation.",
        tactics=["AML.TA0002"],
        maturity="demonstrated",
        attack_reference_id="T1596",
        attack_reference_url="https://attack.mitre.org/techniques/T1596/",
        subtechnique_of=None,
        created_date="2021-05-13",
        modified_date="2025-04-09",
    )
    upsert_atlas_technique(
        "AML.T0000.000",
        name="Journals and Conference Proceedings",
        description="Sub-technique on academic literature.",
        tactics=["AML.TA0002"],
        maturity="feasible",
        attack_reference_id=None,
        attack_reference_url=None,
        subtechnique_of="AML.T0000",
    )
    upsert_atlas_case_study(
        "AML.CS0000",
        name="Evasion of Deep Learning Detector",
        description="Real-world adversarial example incident.",
        techniques_used=["AML.T0000", "AML.T0043"],
    )


# --- atlas_technique_lookup ---


def test_atlas_technique_lookup_returns_record():
    _seed_atlas()
    r = client.get("/v1/atlas/AML.T0000")
    assert r.status_code == 200
    body = r.json()
    assert body["technique_id"] == "AML.T0000"
    assert body["name"] == "Search Open Technical Databases"
    assert body["tactics"] == ["AML.TA0002"]
    assert body["maturity"] == "demonstrated"
    assert body["attack_reference_id"] == "T1596"


def test_atlas_technique_lookup_404_unknown():
    r = client.get("/v1/atlas/AML.T9999")
    assert r.status_code == 404


def test_atlas_technique_lookup_400_invalid_format():
    r = client.get("/v1/atlas/notatechnique")
    assert r.status_code == 400


def test_atlas_technique_lookup_pivot_hints():
    """attack_reference_id present → next_calls includes d3fend_defense_for_attack + cve_search."""
    _seed_atlas()
    r = client.get("/v1/atlas/AML.T0000")
    assert r.status_code == 200
    tools = {h["tool"] for h in r.json().get("next_calls") or []}
    assert "d3fend_defense_for_attack" in tools
    assert "cve_search" in tools
    assert "atlas_case_study_search" in tools


def test_atlas_technique_lookup_subtechnique_pivots_to_parent():
    _seed_atlas()
    r = client.get("/v1/atlas/AML.T0000.000")
    assert r.status_code == 200
    tools = {h["tool"]: h for h in r.json().get("next_calls") or []}
    assert "atlas_technique_lookup" in tools
    assert tools["atlas_technique_lookup"]["input"] == "AML.T0000"


def test_atlas_technique_lookup_no_attack_ref_no_d3fend_hint():
    """Sub-technique has attack_reference_id=None → no d3fend bridge hint."""
    _seed_atlas()
    r = client.get("/v1/atlas/AML.T0000.000")
    tools = {h["tool"] for h in r.json().get("next_calls") or []}
    assert "d3fend_defense_for_attack" not in tools


# --- atlas_technique_search ---


def test_atlas_technique_search_by_keyword():
    _seed_atlas()
    r = client.get("/v1/atlas/techniques", params={"keyword": "search"})
    assert r.status_code == 200
    body = r.json()
    ids = {row["technique_id"] for row in body["results"]}
    assert "AML.T0000" in ids


def test_atlas_technique_search_by_tactic():
    _seed_atlas()
    r = client.get("/v1/atlas/techniques", params={"tactic": "AML.TA0002"})
    assert r.status_code == 200
    ids = {row["technique_id"] for row in r.json()["results"]}
    assert {"AML.T0000", "AML.T0000.000"}.issubset(ids)


def test_atlas_technique_search_invalid_tactic_400():
    r = client.get("/v1/atlas/techniques", params={"tactic": "BAD"})
    assert r.status_code == 400


def test_atlas_technique_search_invalid_maturity_400():
    r = client.get("/v1/atlas/techniques", params={"maturity": "ghost"})
    assert r.status_code == 400


def test_atlas_technique_search_whitespace_keyword_400():
    """Whitespace-only keyword bypasses min_length=2 — must be rejected post-strip."""
    r = client.get("/v1/atlas/techniques", params={"keyword": "  "})
    assert r.status_code == 400


def test_atlas_case_study_search_whitespace_keyword_400():
    r = client.get("/v1/atlas/case-studies", params={"keyword": "  "})
    assert r.status_code == 400


def test_atlas_technique_search_emits_drilldown_hint():
    _seed_atlas()
    r = client.get("/v1/atlas/techniques", params={"keyword": "search"})
    body = r.json()
    if body["results"]:
        tools = {h["tool"] for h in body.get("next_calls") or []}
        assert "atlas_technique_lookup" in tools


# --- atlas_case_study_lookup ---


def test_atlas_case_study_lookup_returns_record():
    _seed_atlas()
    r = client.get("/v1/atlas/case-studies/AML.CS0000")
    assert r.status_code == 200
    body = r.json()
    assert body["case_study_id"] == "AML.CS0000"
    assert "AML.T0000" in body["techniques_used"]
    assert "AML.T0043" in body["techniques_used"]


def test_atlas_case_study_lookup_404_unknown():
    r = client.get("/v1/atlas/case-studies/AML.CS9999")
    assert r.status_code == 404


def test_atlas_case_study_lookup_pivot_hints():
    _seed_atlas()
    r = client.get("/v1/atlas/case-studies/AML.CS0000")
    inputs = {h["input"] for h in r.json().get("next_calls") or []}
    assert "AML.T0000" in inputs
    assert "AML.T0043" in inputs


# --- atlas_case_study_search ---


def test_atlas_case_study_search_by_technique():
    _seed_atlas()
    r = client.get("/v1/atlas/case-studies", params={"technique_id": "AML.T0043"})
    assert r.status_code == 200
    ids = {row["case_study_id"] for row in r.json()["results"]}
    assert "AML.CS0000" in ids


def test_atlas_case_study_search_by_keyword():
    _seed_atlas()
    r = client.get("/v1/atlas/case-studies", params={"keyword": "evasion"})
    assert r.status_code == 200
    ids = {row["case_study_id"] for row in r.json()["results"]}
    assert "AML.CS0000" in ids


def test_atlas_case_study_search_invalid_technique_id_400():
    r = client.get("/v1/atlas/case-studies", params={"technique_id": "bad"})
    assert r.status_code == 400
