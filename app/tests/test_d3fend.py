"""Tests for MITRE D3FEND routes — d3fend/routes.py."""

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def _seed_d3fend():
    """Seed two defenses + their attack mappings for routing tests."""
    from db import upsert_d3fend_attack_mappings, upsert_d3fend_defense

    upsert_d3fend_defense(
        "TokenBinding",
        label="Token Binding",
        uri="http://d3fend.mitre.org/ontologies/d3fend.owl#TokenBinding",
        parent_label="Credential Hardening",
        description=None,
        tactic="Harden",
        artifact="Access Token",
    )
    upsert_d3fend_defense(
        "FileHashing",
        label="File Hashing",
        uri="http://d3fend.mitre.org/ontologies/d3fend.owl#FileHashing",
        parent_label="File Analysis",
        description=None,
        tactic="Detect",
        artifact="File",
    )
    upsert_d3fend_attack_mappings(
        [
            {
                "defense_id": "TokenBinding",
                "attack_technique_id": "T1550.001",
                "attack_label": "Application Access Token",
                "attack_tactic": "Lateral Movement",
            },
            {
                "defense_id": "TokenBinding",
                "attack_technique_id": "T1539",
                "attack_label": "Steal Web Session Cookie",
                "attack_tactic": "Credential Access",
            },
            {
                "defense_id": "FileHashing",
                "attack_technique_id": "T1059",
                "attack_label": "Command and Scripting Interpreter",
                "attack_tactic": "Execution",
            },
            {
                "defense_id": "FileHashing",
                "attack_technique_id": "T1550.001",
                "attack_label": "Application Access Token",
                "attack_tactic": "Lateral Movement",
            },
        ]
    )


# --- d3fend_defense_lookup ---


def test_d3fend_defense_lookup_returns_record():
    _seed_d3fend()
    r = client.get("/v1/d3fend/TokenBinding")
    assert r.status_code == 200
    body = r.json()
    assert body["defense_id"] == "TokenBinding"
    assert body["label"] == "Token Binding"
    assert body["tactic"] == "Harden"
    assert body["artifact"] == "Access Token"
    assert set(body["attack_techniques"]) == {"T1550.001", "T1539"}


def test_d3fend_defense_lookup_404_unknown():
    r = client.get("/v1/d3fend/Nonexistent")
    assert r.status_code == 404


def test_d3fend_defense_lookup_400_invalid_format():
    r = client.get("/v1/d3fend/with spaces")
    assert r.status_code == 400


def test_d3fend_defense_lookup_pivot_hints():
    _seed_d3fend()
    r = client.get("/v1/d3fend/TokenBinding")
    tools = {h["tool"] for h in r.json().get("next_calls") or []}
    assert "atlas_technique_search" in tools
    assert "cve_search" in tools


# --- d3fend_defense_search ---


def test_d3fend_defense_search_by_keyword():
    _seed_d3fend()
    r = client.get("/v1/d3fend/defenses", params={"keyword": "token"})
    assert r.status_code == 200
    ids = {row["defense_id"] for row in r.json()["results"]}
    assert "TokenBinding" in ids


def test_d3fend_defense_search_by_tactic():
    _seed_d3fend()
    r = client.get("/v1/d3fend/defenses", params={"tactic": "Harden"})
    assert r.status_code == 200
    ids = {row["defense_id"] for row in r.json()["results"]}
    assert ids == {"TokenBinding"}


def test_d3fend_defense_search_invalid_tactic_400():
    r = client.get("/v1/d3fend/defenses", params={"tactic": "BogusTactic"})
    assert r.status_code == 400


def test_d3fend_defense_search_whitespace_keyword_400():
    r = client.get("/v1/d3fend/defenses", params={"keyword": "  "})
    assert r.status_code == 400


# --- d3fend_defense_for_attack (CRITICAL — reverse lookup) ---


def test_d3fend_for_attack_returns_all_defenses():
    """CRITICAL: M:N reverse lookup must return both defenses for shared T-code."""
    _seed_d3fend()
    r = client.get("/v1/d3fend/attack/T1550.001")
    assert r.status_code == 200
    body = r.json()
    assert body["attack_technique_id"] == "T1550.001"
    assert body["total"] == 2
    ids = {d["defense_id"] for d in body["defenses"]}
    assert ids == {"TokenBinding", "FileHashing"}


def test_d3fend_for_attack_single_defense():
    _seed_d3fend()
    r = client.get("/v1/d3fend/attack/T1059")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1
    assert body["defenses"][0]["defense_id"] == "FileHashing"


def test_d3fend_for_attack_unknown_tcode_returns_empty():
    """No D3FEND mapping → 200 with empty defenses (gap is signal)."""
    _seed_d3fend()
    r = client.get("/v1/d3fend/attack/T9999")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 0
    assert body["defenses"] == []
    assert body.get("next_calls") in (None, [])


def test_d3fend_for_attack_400_invalid_format():
    r = client.get("/v1/d3fend/attack/notaTcode")
    assert r.status_code == 400


def test_d3fend_for_attack_coverage_by_tactic():
    _seed_d3fend()
    r = client.get("/v1/d3fend/attack/T1550.001")
    body = r.json()
    # TokenBinding=Harden, FileHashing=Detect → one of each
    assert body["coverage_by_tactic"] == {"Harden": 1, "Detect": 1}


# --- d3fend_attack_coverage (POST batch) ---


def test_d3fend_coverage_batch():
    _seed_d3fend()
    r = client.post(
        "/v1/d3fend/coverage",
        json={"attack_technique_ids": ["T1550.001", "T1059", "T9999"]},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["coverage_by_tactic"] == {"Harden": 1, "Detect": 1}
    assert "T9999" in body["undefended_techniques"]
    assert set(body["defended_techniques"]) == {"T1550.001", "T1059"}


def test_d3fend_coverage_undefended_emits_pivot_hints():
    _seed_d3fend()
    r = client.post(
        "/v1/d3fend/coverage",
        json={"attack_technique_ids": ["T9999", "T8888"]},
    )
    body = r.json()
    inputs = {h["input"] for h in body.get("next_calls") or []}
    assert {"T9999", "T8888"}.issubset(inputs)


def test_d3fend_coverage_empty_input():
    r = client.post("/v1/d3fend/coverage", json={"attack_technique_ids": []})
    assert r.status_code == 200
    body = r.json()
    assert body["queried_techniques"] == []
    assert body["coverage_by_tactic"] == {}


def test_d3fend_coverage_filters_invalid_tcodes():
    _seed_d3fend()
    r = client.post(
        "/v1/d3fend/coverage",
        json={"attack_technique_ids": ["T1059", "not-a-tcode", "T1550.001"]},
    )
    assert r.status_code == 200
    body = r.json()
    assert set(body["queried_techniques"]) == {"T1059", "T1550.001"}
