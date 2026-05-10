"""Tests for D3FEND mappings sync — sync_d3fend()."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch


def _binding(def_uri, def_label, parent, def_tactic, def_artifact, off_id, off_label, off_tactic):
    """Build one SPARQL binding row in the format the upstream returns."""
    return {
        "def_tech": {"type": "uri", "value": def_uri},
        "def_tech_label": {"type": "literal", "value": def_label},
        "top_def_tech_label": {"type": "literal", "value": parent},
        "def_tactic_label": {"type": "literal", "value": def_tactic},
        "def_artifact_label": {"type": "literal", "value": def_artifact},
        "off_tech_id": {"type": "literal", "value": off_id},
        "off_tech_label": {"type": "literal", "value": off_label},
        "off_tactic_label": {"type": "literal", "value": off_tactic},
    }


SAMPLE_D3FEND = {
    "head": {"vars": ["def_tech", "off_tech_id"]},
    "results": {
        "bindings": [
            _binding(
                "http://d3fend.mitre.org/ontologies/d3fend.owl#TokenBinding",
                "Token Binding",
                "Credential Hardening",
                "Harden",
                "Access Token",
                "T1550.001",
                "Application Access Token",
                "Lateral Movement",
            ),
            _binding(
                "http://d3fend.mitre.org/ontologies/d3fend.owl#TokenBinding",
                "Token Binding",
                "Credential Hardening",
                "Harden",
                "Access Token",
                "T1539",
                "Steal Web Session Cookie",
                "Credential Access",
            ),
            _binding(
                "http://d3fend.mitre.org/ontologies/d3fend.owl#FileHashing",
                "File Hashing",
                "File Analysis",
                "Detect",
                "File",
                "T1059",
                "Command and Scripting Interpreter",
                "Execution",
            ),
            _binding(
                "http://d3fend.mitre.org/ontologies/d3fend.owl#FileHashing",
                "File Hashing",
                "File Analysis",
                "Detect",
                "File",
                "T1550.001",
                "Application Access Token",
                "Lateral Movement",
            ),
        ],
    },
}


def _mock_client_returning(payload: dict, content_size: int | None = None):
    import json as _json

    body = _json.dumps(payload).encode()
    mock_resp = MagicMock()
    mock_resp.content = b"x" * content_size if content_size is not None else body
    mock_resp.json.return_value = payload
    mock_resp.raise_for_status.return_value = None
    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value=mock_resp)
    return mock_client


def test_sync_d3fend_writes_defenses():
    from d3fend import sync as d3_sync

    with patch.object(d3_sync, "_client", _mock_client_returning(SAMPLE_D3FEND)):
        count = asyncio.run(d3_sync.sync_d3fend())
    assert count == 4  # 4 mapping rows

    from db import get_d3fend_defense

    tb = get_d3fend_defense("TokenBinding")
    assert tb is not None
    assert tb["label"] == "Token Binding"
    assert tb["uri"].endswith("#TokenBinding")
    assert tb["parent_label"] == "Credential Hardening"
    assert tb["tactic"] == "Harden"
    assert tb["artifact"] == "Access Token"
    assert set(tb["attack_techniques"]) == {"T1550.001", "T1539"}


def test_sync_d3fend_reverse_lookup():
    from d3fend import sync as d3_sync

    with patch.object(d3_sync, "_client", _mock_client_returning(SAMPLE_D3FEND)):
        asyncio.run(d3_sync.sync_d3fend())

    from db import get_d3fend_defenses_for_attack

    defenses = get_d3fend_defenses_for_attack("T1550.001")
    ids = {d["defense_id"] for d in defenses}
    assert ids == {"TokenBinding", "FileHashing"}

    only_fh = get_d3fend_defenses_for_attack("T1059")
    assert {d["defense_id"] for d in only_fh} == {"FileHashing"}

    none = get_d3fend_defenses_for_attack("T9999")
    assert none == []


def test_sync_d3fend_search_by_tactic():
    from d3fend import sync as d3_sync

    with patch.object(d3_sync, "_client", _mock_client_returning(SAMPLE_D3FEND)):
        asyncio.run(d3_sync.sync_d3fend())

    from db import search_d3fend_defenses

    harden = search_d3fend_defenses(tactic="Harden")
    assert {d["defense_id"] for d in harden} == {"TokenBinding"}

    detect = search_d3fend_defenses(tactic="Detect")
    assert {d["defense_id"] for d in detect} == {"FileHashing"}


def test_sync_d3fend_coverage():
    from d3fend import sync as d3_sync

    with patch.object(d3_sync, "_client", _mock_client_returning(SAMPLE_D3FEND)):
        asyncio.run(d3_sync.sync_d3fend())

    from db import get_d3fend_coverage

    cov = get_d3fend_coverage(["T1550.001", "T1059", "T9999"])
    # Distinct defenses per tactic across the input set:
    # Harden = {TokenBinding}, Detect = {FileHashing}
    assert cov["coverage_by_tactic"] == {"Harden": 1, "Detect": 1}
    assert "T9999" in cov["undefended_techniques"]
    assert set(cov["defended_techniques"]) == {"T1550.001", "T1059"}


def test_sync_d3fend_invalid_tactic_skipped():
    from d3fend import sync as d3_sync

    payload = {
        "results": {
            "bindings": [
                _binding(
                    "http://d3fend.mitre.org/ontologies/d3fend.owl#BogusDefense",
                    "Bogus",
                    "Bogus Parent",
                    "NotARealTactic",
                    "Thing",
                    "T1234",
                    "Bogus Attack",
                    "Bogus Tactic",
                ),
            ],
        },
    }
    with patch.object(d3_sync, "_client", _mock_client_returning(payload)):
        count = asyncio.run(d3_sync.sync_d3fend())
    assert count == 0

    from db import get_d3fend_defense

    assert get_d3fend_defense("BogusDefense") is None


def test_sync_d3fend_marks_status_ok():
    from d3fend import sync as d3_sync

    with patch.object(d3_sync, "_client", _mock_client_returning(SAMPLE_D3FEND)):
        asyncio.run(d3_sync.sync_d3fend())

    from db import get_sync_status

    status = get_sync_status()
    assert status.get("d3fend", {}).get("status") == "ok"
    assert status["d3fend"]["records_count"] == 4
