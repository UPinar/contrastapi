"""Tests for ATLAS YAML sync — sync_atlas()."""

from unittest.mock import MagicMock, patch

SAMPLE_ATLAS_YAML = b"""
id: ATLAS
name: ATLAS
version: 5.5.0
matrices:
  - id: matrix-1
    name: ATLAS Matrix
    techniques:
      - id: AML.T0000
        name: Search Open Technical Databases
        description: |
          Adversaries may search for publicly available research and technical documentation.
        object-type: technique
        tactics:
          - AML.TA0002
        maturity: demonstrated
        ATT&CK-reference:
          id: T1596
          url: https://attack.mitre.org/techniques/T1596/
        created_date: 2021-05-13
        modified_date: 2025-04-09
      - id: AML.T0000.000
        name: Journals and Conference Proceedings
        description: Sub-technique description
        object-type: technique
        subtechnique-of: AML.T0000
        maturity: feasible
case-studies:
  - id: AML.CS0000
    name: Evasion of Deep Learning Detector
    summary: Real-world adversarial example incident
    procedure:
      - technique: AML.T0000
        description: step 1
      - technique: AML.T0043
        description: step 2
"""


def _mock_client_returning(content: bytes):
    mock_resp = MagicMock()
    mock_resp.content = content
    mock_resp.raise_for_status.return_value = None
    mock_client = MagicMock()
    mock_client.get.return_value = mock_resp
    return mock_client


def test_sync_atlas_writes_techniques():
    from atlas import sync as atlas_sync

    with patch.object(atlas_sync, "_client", _mock_client_returning(SAMPLE_ATLAS_YAML)):
        count = atlas_sync.sync_atlas()

    assert count == 3  # 2 techniques + 1 case study

    from db import get_atlas_technique

    tech = get_atlas_technique("AML.T0000")
    assert tech is not None
    assert tech["name"] == "Search Open Technical Databases"
    assert tech["tactics"] == ["AML.TA0002"]
    assert tech["maturity"] == "demonstrated"
    assert tech["attack_reference_id"] == "T1596"
    assert tech["attack_reference_url"].startswith("https://attack.mitre.org/")

    sub = get_atlas_technique("AML.T0000.000")
    assert sub is not None
    assert sub["subtechnique_of"] == "AML.T0000"
    assert sub["attack_reference_id"] is None


def test_sync_atlas_writes_case_studies():
    from atlas import sync as atlas_sync

    with patch.object(atlas_sync, "_client", _mock_client_returning(SAMPLE_ATLAS_YAML)):
        atlas_sync.sync_atlas()

    from db import get_atlas_case_study

    cs = get_atlas_case_study("AML.CS0000")
    assert cs is not None
    assert cs["name"] == "Evasion of Deep Learning Detector"
    assert "AML.T0000" in cs["techniques_used"]
    assert "AML.T0043" in cs["techniques_used"]


def test_sync_atlas_search_by_keyword():
    from atlas import sync as atlas_sync

    with patch.object(atlas_sync, "_client", _mock_client_returning(SAMPLE_ATLAS_YAML)):
        atlas_sync.sync_atlas()

    from db import search_atlas_techniques

    results = search_atlas_techniques(keyword="search")
    ids = {r["technique_id"] for r in results}
    assert "AML.T0000" in ids


def test_sync_atlas_search_by_tactic():
    from atlas import sync as atlas_sync

    with patch.object(atlas_sync, "_client", _mock_client_returning(SAMPLE_ATLAS_YAML)):
        atlas_sync.sync_atlas()

    from db import search_atlas_techniques

    results = search_atlas_techniques(tactic="AML.TA0002")
    assert any(r["technique_id"] == "AML.T0000" for r in results)


def test_sync_atlas_oversize_refuses():
    from atlas import sync as atlas_sync

    huge = b"x" * (atlas_sync.ATLAS_MAX_BYTES + 1)
    with patch.object(atlas_sync, "_client", _mock_client_returning(huge)):
        count = atlas_sync.sync_atlas()
    assert count == 0


def test_sync_atlas_marks_status_ok():
    from atlas import sync as atlas_sync

    with patch.object(atlas_sync, "_client", _mock_client_returning(SAMPLE_ATLAS_YAML)):
        atlas_sync.sync_atlas()

    from db import get_sync_status

    status = get_sync_status()
    assert status.get("atlas", {}).get("status") == "ok"
    assert status["atlas"]["records_count"] >= 3
