"""Tests for config.py"""

import os
from pathlib import Path


def test_base_dir_is_app():
    from config import BASE_DIR
    assert BASE_DIR.name == "app"
    assert BASE_DIR.is_dir()


def test_db_paths_are_path_objects():
    from config import API_DB_PATH, CVE_DB_PATH, CACHE_DB_PATH
    assert isinstance(API_DB_PATH, Path)
    assert isinstance(CVE_DB_PATH, Path)
    assert isinstance(CACHE_DB_PATH, Path)


def test_db_paths_fallback_to_local(monkeypatch):
    monkeypatch.delenv("CONTRASTAPI_DB", raising=False)
    monkeypatch.delenv("CONTRASTAPI_CVE_DB", raising=False)
    monkeypatch.delenv("CONTRASTAPI_CACHE_DB", raising=False)
    # Re-import to get fresh values
    import importlib
    import config
    importlib.reload(config)
    # If /var/lib/contrastapi/ doesn't exist, should fallback to BASE_DIR
    if not Path("/var/lib/contrastapi").exists():
        assert "app" in str(config.API_DB_PATH)


def test_rate_limits_positive():
    from config import FREE_HOURLY_LIMIT, PRO_HOURLY_LIMIT
    assert FREE_HOURLY_LIMIT > 0
    assert PRO_HOURLY_LIMIT > FREE_HOURLY_LIMIT


def test_key_prefix():
    from config import KEY_PREFIX, KEY_LENGTH
    assert KEY_PREFIX == "cc_"
    assert KEY_LENGTH == 48


def test_max_domain_length():
    from config import MAX_DOMAIN_LENGTH
    assert MAX_DOMAIN_LENGTH == 253


def test_severity_order():
    from config import SEVERITY_ORDER
    assert SEVERITY_ORDER["critical"] < SEVERITY_ORDER["high"]
    assert SEVERITY_ORDER["high"] < SEVERITY_ORDER["medium"]
    assert SEVERITY_ORDER["medium"] < SEVERITY_ORDER["low"]


def test_env_override_db_path(monkeypatch, tmp_path):
    db_file = tmp_path / "test.db"
    monkeypatch.setenv("CONTRASTAPI_DB", str(db_file))
    import importlib
    import config
    importlib.reload(config)
    assert config.API_DB_PATH == db_file
