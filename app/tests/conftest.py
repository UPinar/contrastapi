"""Shared test fixtures for ContrastAPI."""

import pytest


@pytest.fixture(autouse=True)
def temp_dbs(tmp_path, monkeypatch):
    """Provide isolated temp databases for every test."""
    monkeypatch.setenv("TESTING", "1")
    monkeypatch.setenv("CONTRASTAPI_DB", str(tmp_path / "api.db"))
    monkeypatch.setenv("CONTRASTAPI_CVE_DB", str(tmp_path / "cve.db"))
    monkeypatch.setenv("CONTRASTAPI_CACHE_DB", str(tmp_path / "cache.db"))
    import importlib

    import config

    importlib.reload(config)
    import db
    import ratelimit

    importlib.reload(db)
    importlib.reload(ratelimit)
    db.init_all_dbs()
    ratelimit.reset()
    yield
    ratelimit.reset()
    db.close_thread_connections()
