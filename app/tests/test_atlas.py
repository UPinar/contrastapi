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
    """attack_reference_id present → next_calls bridges to D3FEND + ATLAS case studies + sibling tactic search."""
    _seed_atlas()
    r = client.get("/v1/atlas/AML.T0000")
    assert r.status_code == 200
    body = r.json()
    hints = body.get("next_calls") or []
    tools = {h["tool"] for h in hints}
    assert "d3fend_defense_for_attack" in tools
    assert "atlas_case_study_search" in tools
    # v1.19.3: sibling-technique chain via tactic filter.
    if body.get("tactics"):
        sibling_hints = [h for h in hints if h["tool"] == "atlas_technique_search"]
        assert len(sibling_hints) == 1
        assert sibling_hints[0]["input"] == body["tactics"][0]
    # cve_search does not accept ATT&CK T-codes; pivot removed in v1.19.2.
    assert "cve_search" not in tools


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
    """v1.20.0: 5 atlas_technique_lookup hints consolidated to a single
    bulk_atlas_technique_lookup hint that drills into ALL techniques in one call."""
    _seed_atlas()
    r = client.get("/v1/atlas/case-studies/AML.CS0000")
    body = r.json()
    hints = body.get("next_calls") or []
    assert len(hints) == 1, f"expected 1 consolidated hint, got {len(hints)}: {hints}"
    h = hints[0]
    assert h["tool"] == "bulk_atlas_technique_lookup"
    # The consolidated input is a comma-joined list of all techniques_used ids.
    ids_in_input = set(h["input"].split(","))
    assert "AML.T0000" in ids_in_input
    assert "AML.T0043" in ids_in_input
    # The full id list also lives in techniques_used so the agent can call
    # the bulk tool directly with that array.
    assert set(body["techniques_used"]) == ids_in_input


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


# --- v1.20.0 Tier 3 #4: sub-technique tactics inheritance ---


def _seed_inherit_subtech():
    """Seed a parent + sub-technique where the sub-tech has empty tactics
    (mirrors ATLAS upstream behaviour for sub-techniques)."""
    from db import upsert_atlas_technique

    upsert_atlas_technique(
        "AML.T0051",
        name="LLM Prompt Injection",
        description="Adversaries craft inputs that override the LLM's intended instructions.",
        tactics=["AML.TA0005"],
        maturity="demonstrated",
        attack_reference_id=None,
        attack_reference_url=None,
        subtechnique_of=None,
    )
    upsert_atlas_technique(
        "AML.T0051.999",
        name="Prompt Injection: Direct",
        description="Direct prompt injection sub-technique.",
        tactics=[],  # ATLAS upstream leaves sub-tech tactics empty
        maturity="demonstrated",
        attack_reference_id=None,
        attack_reference_url=None,
        subtechnique_of="AML.T0051",
    )


def test_atlas_subtech_lookup_inherits_tactics_from_parent():
    _seed_inherit_subtech()
    r = client.get("/v1/atlas/AML.T0051.999")
    assert r.status_code == 200
    body = r.json()
    assert body["tactics"] == ["AML.TA0005"], "sub-tech must inherit parent tactics"
    assert body["inherited_tactics"] is True


def test_atlas_subtech_lookup_native_tactics_no_flag():
    """Sub-technique with its own non-empty tactics is not flagged inherited."""
    _seed_atlas()  # AML.T0000.000 has its own tactics=['AML.TA0002']
    r = client.get("/v1/atlas/AML.T0000.000")
    body = r.json()
    assert body["tactics"] == ["AML.TA0002"]
    assert body.get("inherited_tactics") is None


def test_atlas_subtech_lookup_no_parent_no_inheritance():
    """Sub-technique whose parent is missing in DB stays empty + no flag."""
    from db import upsert_atlas_technique

    upsert_atlas_technique(
        "AML.T9999.001",
        name="Orphan sub-tech",
        description="Parent not in DB.",
        tactics=[],
        maturity="feasible",
        attack_reference_id=None,
        attack_reference_url=None,
        subtechnique_of="AML.T9999",
    )
    r = client.get("/v1/atlas/AML.T9999.001")
    assert r.status_code == 200
    body = r.json()
    assert body["tactics"] == []
    assert body.get("inherited_tactics") is None


def test_atlas_subtech_search_inherits_tactics():
    """Sub-tech rows in search results also receive inherited tactics."""
    _seed_inherit_subtech()
    r = client.get("/v1/atlas/techniques", params={"keyword": "prompt"})
    assert r.status_code == 200
    rows = {row["technique_id"]: row for row in r.json()["results"]}
    sub = rows.get("AML.T0051.999")
    assert sub is not None
    assert sub["tactics"] == ["AML.TA0005"]
    assert sub["inherited_tactics"] is True


# --- v1.20.0 Tier 3 #5: atlas_case_study_lookup slim parity ---


def _seed_atlas_long_description():
    from db import upsert_atlas_case_study

    long_desc = "A" * 800  # > 240-char preview cap
    upsert_atlas_case_study(
        "AML.CS9000",
        name="Long incident",
        description=long_desc,
        techniques_used=["AML.T0000"],
    )
    return long_desc


def test_atlas_case_study_lookup_slim_default_truncates():
    long_desc = _seed_atlas_long_description()
    r = client.get("/v1/atlas/case-studies/AML.CS9000")
    assert r.status_code == 200
    desc = r.json()["description"]
    assert len(desc) < len(long_desc)
    assert desc.endswith("...")


def test_atlas_case_study_lookup_include_full_returns_full():
    long_desc = _seed_atlas_long_description()
    r = client.get("/v1/atlas/case-studies/AML.CS9000", params={"include": "full"})
    assert r.status_code == 200
    assert r.json()["description"] == long_desc


def test_atlas_case_study_lookup_include_invalid_400():
    r = client.get("/v1/atlas/case-studies/AML.CS0000", params={"include": "verbose"})
    assert r.status_code == 400


def test_atlas_case_study_lookup_short_description_unchanged():
    """A short description should pass through unchanged in slim default — no '...' suffix."""
    _seed_atlas()  # AML.CS0000 has short description
    r = client.get("/v1/atlas/case-studies/AML.CS0000")
    desc = r.json().get("description") or ""
    assert not desc.endswith("...")


# --- v1.20.0 Tier 4 #7: bulk_atlas_technique_lookup ---


def test_bulk_atlas_technique_lookup_happy_path():
    _seed_atlas()
    r = client.post("/v1/atlas/techniques/bulk", json={"technique_ids": ["AML.T0000", "AML.T0000.000"]})
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 2
    assert body["successful"] == 2
    assert body["failed"] == 0
    assert body["partial"] is False
    by_id = {item["technique_id"]: item for item in body["results"]}
    assert by_id["AML.T0000"]["status"] == "ok"
    assert by_id["AML.T0000"]["technique"]["name"] == "Search Open Technical Databases"
    # next_calls passes through (parent lookup pivot for sub-tech)
    sub = by_id["AML.T0000.000"]["technique"]
    sub_tools = {h["tool"] for h in (sub.get("next_calls") or [])}
    assert "atlas_technique_lookup" in sub_tools


def test_bulk_atlas_technique_lookup_mixed_outcomes():
    _seed_atlas()
    r = client.post(
        "/v1/atlas/techniques/bulk",
        json={"technique_ids": ["AML.T0000", "AML.T9999", "not-a-technique", "aml.t0000"]},
    )
    assert r.status_code == 200
    body = r.json()
    # 'aml.t0000' normalizes + de-dups to AML.T0000 → 3 unique items
    assert body["total"] == 3
    by_id = {item["technique_id"]: item for item in body["results"]}
    assert by_id["AML.T0000"]["status"] == "ok"
    assert by_id["AML.T9999"]["status"] == "not_found"
    assert by_id["NOT-A-TECHNIQUE"]["status"] == "invalid_format"
    assert body["successful"] == 1
    assert body["failed"] == 2
    assert body["partial"] is True


def test_bulk_atlas_technique_lookup_inherits_parent_tactics():
    """Sub-tech inheritance applies inside the bulk response too."""
    _seed_inherit_subtech()
    r = client.post("/v1/atlas/techniques/bulk", json={"technique_ids": ["AML.T0051.999"]})
    assert r.status_code == 200
    item = r.json()["results"][0]
    assert item["status"] == "ok"
    assert item["technique"]["tactics"] == ["AML.TA0005"]
    assert item["technique"]["inherited_tactics"] is True


def test_bulk_atlas_technique_lookup_empty_input():
    r = client.post("/v1/atlas/techniques/bulk", json={"technique_ids": []})
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 0
    assert body["results"] == []
    assert body["partial"] is False


def test_bulk_atlas_technique_lookup_caps_at_50():
    """Server enforces the 50-id absolute cap via Pydantic max_length."""
    ids = [f"AML.T{i:04d}" for i in range(60)]
    r = client.post("/v1/atlas/techniques/bulk", json={"technique_ids": ids})
    # Pydantic validation rejects >50 with 422 before the route runs.
    assert r.status_code == 422


def test_bulk_atlas_technique_lookup_free_tier_capped_at_10():
    """Free tier hits the FREE_BULK_LIMIT=10 ceiling with HTTP 422."""
    ids = [f"AML.T{i:04d}" for i in range(11)]
    r = client.post("/v1/atlas/techniques/bulk", json={"technique_ids": ids})
    # 11 ids exceeds free-tier cap (10) → 422 before any DB lookup.
    assert r.status_code == 422
    assert "tier" in r.text.lower() or "limit" in r.text.lower()


def test_bulk_atlas_technique_lookup_dedup_preserves_first_occurrence():
    _seed_atlas()
    r = client.post(
        "/v1/atlas/techniques/bulk",
        json={"technique_ids": ["AML.T0000", "AML.T0000", "AML.T0000.000"]},
    )
    body = r.json()
    assert body["total"] == 2
    ids_in_order = [item["technique_id"] for item in body["results"]]
    assert ids_in_order == ["AML.T0000", "AML.T0000.000"]


# --- v1.21.0 Bulk parity: error path + 4-state status enum ---


def test_bulk_atlas_technique_lookup_error_path_on_db_exception(monkeypatch):
    """v1.21.0: transient DB exception → status='error' (parity with bulk_cve + bulk_ioc)."""
    _seed_atlas()
    # Patch get_atlas_technique to raise on a specific id
    import atlas.routes as atlas_routes

    original = atlas_routes.get_atlas_technique

    def flaky(tid):
        if tid == "AML.T0000":
            raise RuntimeError("simulated DB I/O error")
        return original(tid)

    monkeypatch.setattr(atlas_routes, "get_atlas_technique", flaky)

    r = client.post(
        "/v1/atlas/techniques/bulk",
        json={"technique_ids": ["AML.T0000", "AML.T0000.000"]},
    )
    assert r.status_code == 200
    body = r.json()
    by_id = {item["technique_id"]: item for item in body["results"]}
    assert by_id["AML.T0000"]["status"] == "error"
    assert "transient" in by_id["AML.T0000"]["error"].lower()
    # The other id still resolves OK — failure is per-item, not per-batch.
    assert by_id["AML.T0000.000"]["status"] == "ok"
    assert body["successful"] == 1
    assert body["failed"] == 1
    assert body["partial"] is True


def test_bulk_endpoints_share_4_state_status_enum():
    """v1.21.0: BulkCveItem + BulkIocItem + BulkAtlasTechniqueItem hepsi {ok, error, not_found, invalid_format}."""
    from typing import get_args

    from schemas import BulkAtlasTechniqueItem, BulkCveItem, BulkIocItem

    expected = {"ok", "error", "not_found", "invalid_format"}
    for cls in (BulkCveItem, BulkIocItem, BulkAtlasTechniqueItem):
        status_field = cls.model_fields["status"]
        # Pydantic Literal types: get_args returns the tuple of allowed values
        states = set(get_args(status_field.annotation))
        assert states == expected, f"{cls.__name__}.status states {states} != {expected}"


# --- v1.20.0 Tier 3 #8: exclude_id sibling-tactic self-skip ---


def test_atlas_technique_search_exclude_id_drops_self():
    """tactic=AML.TA0002 returns AML.T0000 + AML.T0000.000; exclude_id removes T0000."""
    _seed_atlas()
    r = client.get(
        "/v1/atlas/techniques",
        params={"tactic": "AML.TA0002", "exclude_id": "AML.T0000"},
    )
    assert r.status_code == 200
    ids = {row["technique_id"] for row in r.json()["results"]}
    assert "AML.T0000" not in ids


def test_atlas_technique_search_exclude_id_invalid_400():
    r = client.get("/v1/atlas/techniques", params={"exclude_id": "not-a-technique"})
    assert r.status_code == 400


def test_atlas_technique_lookup_pivot_emits_exclude_id_params():
    """v1.20.0: sibling-tactic pivot from atlas_technique_lookup carries
    params={'exclude_id': self_id} so it does not echo self back."""
    _seed_atlas()
    r = client.get("/v1/atlas/AML.T0000")
    hints = r.json().get("next_calls") or []
    sibling = next((h for h in hints if h["tool"] == "atlas_technique_search"), None)
    assert sibling is not None
    assert sibling.get("params", {}).get("exclude_id") == "AML.T0000"


def test_atlas_case_study_search_invalid_technique_id_400():
    r = client.get("/v1/atlas/case-studies", params={"technique_id": "bad"})
    assert r.status_code == 400


# --- Slim/full description toggle (v1.19.1 token efficiency) ---


def _seed_long_description():
    """Seed a technique with a long description to exercise the truncation path."""
    from db import upsert_atlas_technique

    long = "X" * 1000
    upsert_atlas_technique(
        "AML.T7777",
        name="Long Desc Technique",
        description=long,
        tactics=["AML.TA0002"],
        maturity="demonstrated",
        attack_reference_id=None,
        attack_reference_url=None,
    )


def test_atlas_technique_search_slim_truncates_description():
    _seed_long_description()
    r = client.get("/v1/atlas/techniques", params={"keyword": "long desc"})
    assert r.status_code == 200
    row = next(x for x in r.json()["results"] if x["technique_id"] == "AML.T7777")
    assert row["description"].endswith("...")
    assert len(row["description"]) <= 250  # 240 + "..."


def test_atlas_technique_search_include_full_keeps_description():
    _seed_long_description()
    r = client.get("/v1/atlas/techniques", params={"keyword": "long desc", "include": "full"})
    assert r.status_code == 200
    row = next(x for x in r.json()["results"] if x["technique_id"] == "AML.T7777")
    assert len(row["description"]) == 1000
    assert not row["description"].endswith("...")


def test_atlas_technique_search_invalid_include_400():
    r = client.get("/v1/atlas/techniques", params={"include": "bogus"})
    assert r.status_code == 400


def test_atlas_case_study_search_slim_truncates_description():
    from db import upsert_atlas_case_study

    long = "Y" * 1000
    upsert_atlas_case_study(
        "AML.CS7777",
        name="Long Desc Case",
        description=long,
        techniques_used=["AML.T0000"],
    )
    r = client.get("/v1/atlas/case-studies", params={"keyword": "long desc"})
    assert r.status_code == 200
    row = next(x for x in r.json()["results"] if x["case_study_id"] == "AML.CS7777")
    assert row["description"].endswith("...")
    assert len(row["description"]) <= 250
