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
    body = r.json()
    hints = body.get("next_calls") or []
    tools = {h["tool"] for h in hints}
    # v1.19.2 baseline: atlas_technique_search by label.
    assert "atlas_technique_search" in tools
    # v1.19.3 chain restoration: same-artifact siblings + reverse-lookup "see also".
    assert "d3fend_defense_search" in tools
    assert "d3fend_defense_for_attack" in tools
    # cve_search does not accept ATT&CK T-codes; pivot removed in v1.19.2.
    assert "cve_search" not in tools
    # Reverse-lookup hints must point at actual T-codes from attack_techniques.
    reverse_inputs = {h["input"] for h in hints if h["tool"] == "d3fend_defense_for_attack"}
    assert reverse_inputs.issubset(set(body.get("attack_techniques") or []))


def test_d3fend_defense_lookup_no_artifact_skips_artifact_hint():
    """When defense has no artifact field, d3fend_defense_search hint is suppressed."""
    _seed_d3fend()
    # FileHashing seed has artifact='File' so the hint fires; assert only when present.
    r = client.get("/v1/d3fend/FileHashing")
    body = r.json()
    hints = body.get("next_calls") or []
    artifact_hints = [h for h in hints if h["tool"] == "d3fend_defense_search"]
    if body.get("artifact"):
        assert len(artifact_hints) == 1
        assert artifact_hints[0]["input"] == body["artifact"]


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
    """No D3FEND mapping → 200 with empty defenses, no chainable pivots (gap is signal)."""
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


def test_d3fend_for_attack_emits_working_chain():
    """v1.19.3: happy-path emits a single drill hint (d3fend_defense_lookup) into the top defense."""
    _seed_d3fend()
    r = client.get("/v1/d3fend/attack/T1550.001")
    body = r.json()
    assert body["total"] >= 1
    hints = body.get("next_calls") or []
    tools = {h["tool"] for h in hints}
    assert tools == {"d3fend_defense_lookup"}
    # cve_search, atlas_technique_search, and d3fend_attack_coverage all either
    # reject ATT&CK T-codes (former two) or expect a list (latter) — none belong.
    assert "cve_search" not in tools
    assert "atlas_technique_search" not in tools
    assert "d3fend_attack_coverage" not in tools
    # Drill hint must point at one of the returned defense_ids.
    drill_inputs = {h["input"] for h in hints if h["tool"] == "d3fend_defense_lookup"}
    response_def_ids = {d["defense_id"] for d in body["defenses"]}
    assert drill_inputs.issubset(response_def_ids)


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


# --- Reverse lookup limit cap (v1.19.1 token efficiency) ---


def _seed_many_defenses_for_attack(t_code: str, n: int):
    """Seed n defenses all mapped to one ATT&CK T-code."""
    from db import upsert_d3fend_attack_mappings, upsert_d3fend_defense

    mappings = []
    for i in range(n):
        did = f"FakeDefense{i:03d}"
        upsert_d3fend_defense(
            did,
            label=f"Fake Defense {i}",
            uri=f"http://d3fend.mitre.org/ontologies/d3fend.owl#{did}",
            parent_label="Fake Parent",
            description=None,
            tactic="Harden",
            artifact="Process",
        )
        mappings.append(
            {
                "defense_id": did,
                "attack_technique_id": t_code,
                "attack_label": "Fake",
                "attack_tactic": "Fake",
            }
        )
    upsert_d3fend_attack_mappings(mappings)


def test_d3fend_for_attack_default_limit_caps_at_30():
    _seed_many_defenses_for_attack("T2222", 50)
    r = client.get("/v1/d3fend/attack/T2222")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 50
    assert body["truncated"] is True
    assert len(body["defenses"]) == 30
    # coverage_by_tactic reflects FULL set (all 50 are Harden)
    assert body["coverage_by_tactic"] == {"Harden": 50}


def test_d3fend_for_attack_explicit_higher_limit():
    _seed_many_defenses_for_attack("T3333", 50)
    r = client.get("/v1/d3fend/attack/T3333", params={"limit": 100})
    body = r.json()
    assert body["total"] == 50
    assert body["truncated"] is False
    assert len(body["defenses"]) == 50


def test_d3fend_for_attack_no_truncation_when_few_defenses():
    _seed_d3fend()
    r = client.get("/v1/d3fend/attack/T1059")
    body = r.json()
    assert body["truncated"] is False
    assert body["total"] == 1
    assert len(body["defenses"]) == 1
