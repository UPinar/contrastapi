"""Tests for `_warn_if_paths_under_base_dir` startup guard.

If any operational path falls back to BASE_DIR-relative (env var unset),
the operator forgot to set the corresponding systemd EnvironmentFile entry —
a warning at startup makes the slip visible immediately instead of being
noticed days later when the data is in the wrong place.
"""

import logging

from config import BASE_DIR, settings
from core.lifespan import _warn_if_paths_under_base_dir


def test_no_warning_when_all_paths_outside_base_dir(monkeypatch, caplog, tmp_path):
    """When all operational paths resolve outside BASE_DIR, no warning."""
    monkeypatch.setattr(settings, "api_db", tmp_path / "api.db")
    monkeypatch.setattr(settings, "cve_db", tmp_path / "cve.db")
    monkeypatch.setattr(settings, "cache_db", tmp_path / "cache.db")
    monkeypatch.setattr(settings, "sigma_path", tmp_path / "sigma")
    monkeypatch.setattr(settings, "mcp_tool_log_path", tmp_path / "mcp.jsonl")
    monkeypatch.setattr(settings, "glama_manifest_path", tmp_path / "glama.json")
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="contrastapi"):
        _warn_if_paths_under_base_dir()
    assert not any("fell back to BASE_DIR" in r.getMessage() for r in caplog.records)


def test_warning_lists_all_unset_env_names(monkeypatch, caplog):
    """All 6 paths under BASE_DIR → warning names all 6 env vars."""
    monkeypatch.setattr(settings, "api_db", BASE_DIR / "api.db")
    monkeypatch.setattr(settings, "cve_db", BASE_DIR / "cve.db")
    monkeypatch.setattr(settings, "cache_db", BASE_DIR / "cache.db")
    monkeypatch.setattr(settings, "sigma_path", BASE_DIR / "sigma")
    monkeypatch.setattr(settings, "mcp_tool_log_path", BASE_DIR / "mcp.jsonl")
    monkeypatch.setattr(settings, "glama_manifest_path", BASE_DIR / "glama.json")
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="contrastapi"):
        _warn_if_paths_under_base_dir()
    msgs = [r.getMessage() for r in caplog.records if "fell back to BASE_DIR" in r.getMessage()]
    assert len(msgs) == 1
    for env in (
        "CONTRASTAPI_DB",
        "CONTRASTAPI_CVE_DB",
        "CONTRASTAPI_CACHE_DB",
        "CONTRASTAPI_SIGMA_PATH",
        "MCP_TOOL_LOG_PATH",
        "GLAMA_MANIFEST_PATH",
    ):
        assert env in msgs[0]


def test_warning_lists_only_unset_env_subset(monkeypatch, caplog, tmp_path):
    """Mixed: some paths inside, some outside → warning lists only the
    inside ones (the env vars the operator forgot to set)."""
    monkeypatch.setattr(settings, "api_db", tmp_path / "api.db")  # set
    monkeypatch.setattr(settings, "cve_db", tmp_path / "cve.db")  # set
    monkeypatch.setattr(settings, "cache_db", tmp_path / "cache.db")  # set
    monkeypatch.setattr(settings, "sigma_path", tmp_path / "sigma")  # set
    monkeypatch.setattr(settings, "mcp_tool_log_path", BASE_DIR / "mcp.jsonl")  # unset
    monkeypatch.setattr(settings, "glama_manifest_path", BASE_DIR / "glama.json")  # unset
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="contrastapi"):
        _warn_if_paths_under_base_dir()
    msgs = [r.getMessage() for r in caplog.records if "fell back to BASE_DIR" in r.getMessage()]
    assert len(msgs) == 1
    assert "MCP_TOOL_LOG_PATH" in msgs[0]
    assert "GLAMA_MANIFEST_PATH" in msgs[0]
    assert "CONTRASTAPI_DB" not in msgs[0]
    assert "CONTRASTAPI_CVE_DB" not in msgs[0]
    assert "CONTRASTAPI_CACHE_DB" not in msgs[0]
    assert "CONTRASTAPI_SIGMA_PATH" not in msgs[0]
