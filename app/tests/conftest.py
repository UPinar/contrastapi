"""Shared test fixtures for ContrastAPI."""

import os

import pytest
from starlette.testclient import TestClient


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "real_asn_country: bypass the autouse _fetch_asn_country mock (for unit tests of the helper itself)",
    )
    config.addinivalue_line(
        "markers",
        "real_firehol: do not mock check_firehol (exercise real trie / fetch)",
    )


# --- Session-scoped: set env vars + reload modules once ---


@pytest.fixture(scope="session", autouse=True)
def _session_dbs(tmp_path_factory):
    """Point the singleton ``settings`` at temp DBs for the whole test session.

    Mutating the existing instance (instead of ``importlib.reload(config)``)
    keeps every module's ``from config import settings`` reference identical
    to ``config.settings`` — reloading orphans those references and
    ``patch("config.settings.X", ...)`` in tests stops affecting modules that
    captured the old singleton.
    """
    from pathlib import Path

    db_dir = tmp_path_factory.mktemp("dbs")
    os.environ["TESTING"] = "1"
    os.environ["CONTRASTAPI_DB"] = str(db_dir / "api.db")
    os.environ["CONTRASTAPI_CVE_DB"] = str(db_dir / "cve.db")
    os.environ["CONTRASTAPI_CACHE_DB"] = str(db_dir / "cache.db")

    import config

    config.settings.api_db = Path(os.environ["CONTRASTAPI_DB"])
    config.settings.cve_db = Path(os.environ["CONTRASTAPI_CVE_DB"])
    config.settings.cache_db = Path(os.environ["CONTRASTAPI_CACHE_DB"])
    config.settings.testing = True

    import db

    db.init_all_dbs()
    yield
    db.close_thread_connections()


# All tables that tests may write to
_CLEANUP_SQL = [
    "DELETE FROM api_keys",
    "DELETE FROM api_usage",
    "DELETE FROM rate_limits",
    "DELETE FROM cves",
    "DELETE FROM cve_products",
    "DELETE FROM sync_status",
    "DELETE FROM domain_cache",
    "DELETE FROM ip_cache",
    "DELETE FROM exploits",
    "DELETE FROM atlas_techniques",
    "DELETE FROM atlas_case_studies",
    "DELETE FROM d3fend_defenses",
    "DELETE FROM d3fend_attack_mappings",
    "DELETE FROM cwes",
]


@pytest.fixture(autouse=True)
def temp_dbs():
    """Clean all tables before each test for isolation."""
    import db

    for sql in _CLEANUP_SQL:
        try:
            with db.get_api_db() as con:
                con.execute(sql)
        except Exception:
            pass
        try:
            with db.get_cve_db() as con:
                con.execute(sql)
        except Exception:
            pass
        try:
            with db.get_cache_db() as con:
                con.execute(sql)
        except Exception:
            pass

    import ratelimit

    ratelimit.reset()
    yield


@pytest.fixture(autouse=True)
def _mock_asn_country(request):
    """Short-circuit RIPE Stat ASN/country fetch in ip_lookup tests by default.

    Tests that want to verify real integration can opt out with
    @pytest.mark.real_asn_country. No try/except: if the patch target is
    missing the test MUST fail loudly (silent bypass would let outbound
    RIPE calls leak from the test suite).
    """
    if request.node.get_closest_marker("real_asn_country"):
        yield
        return
    from unittest.mock import patch

    # Default: `failed=False` — unrelated ip_lookup tests shouldn't see
    # "ripe_stat" in sources_unavailable just because they don't care about
    # ASN. Tests that validate failure paths patch explicitly with failed=True.
    with patch(
        "domain.routes._fetch_asn_country",
        return_value={"asn": None, "asn_name": "", "country": "", "failed": False},
    ):
        yield


@pytest.fixture(autouse=True)
def _mock_firehol(request):
    """Short-circuit FireHOL fetch in route tests by default.

    Patches ``domain.ip_intel.check_firehol``. This works for routes.py because
    it imports the symbol at module scope and calls it directly. Any future
    consumer that either imports the symbol locally (``from domain.ip_intel
    import check_firehol`` inside a function) or patches a different path must
    be aware that this autouse mock only intercepts the ``domain.ip_intel``
    attribute, not re-bound names elsewhere.

    Tests that want to exercise real trie lookups can opt out with
    ``@pytest.mark.real_firehol``.
    """
    if request.node.get_closest_marker("real_firehol"):
        yield
        return
    from unittest.mock import patch

    with patch("domain.ip_intel.check_firehol") as m:
        m.return_value = {"status": "ok", "listed": False, "lists_matched": []}
        yield m


# --- Session-scoped MCP client — shared across all MCP test modules ---
# The MCP StreamableHTTPSessionManager can only be started once per instance;
# sharing a single TestClient prevents "can only be called once" RuntimeError.


@pytest.fixture(scope="session")
def mcp_client(_session_dbs):
    """Single TestClient with lifespan — shared across MCP tests."""
    pytest.importorskip("mcp", reason="mcp package not installed")
    import main

    with TestClient(main.app) as c:
        yield c
