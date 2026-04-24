"""Shared test fixtures for ContrastAPI."""

import importlib
import os

import pytest
from starlette.testclient import TestClient


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "real_asn_country: bypass the autouse _fetch_asn_country mock (for unit tests of the helper itself)",
    )


# --- Session-scoped: set env vars + reload modules once ---


@pytest.fixture(scope="session", autouse=True)
def _session_dbs(tmp_path_factory):
    """Set DB paths once and reload modules a single time."""
    db_dir = tmp_path_factory.mktemp("dbs")
    os.environ["TESTING"] = "1"
    os.environ["CONTRASTAPI_DB"] = str(db_dir / "api.db")
    os.environ["CONTRASTAPI_CVE_DB"] = str(db_dir / "cve.db")
    os.environ["CONTRASTAPI_CACHE_DB"] = str(db_dir / "cache.db")

    import config

    importlib.reload(config)
    import db
    import ratelimit

    importlib.reload(db)
    importlib.reload(ratelimit)
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
