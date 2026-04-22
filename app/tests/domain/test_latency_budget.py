"""Latency budget smoke test for /v1/domain/ endpoint.

Targets Nuclei 10s default timeout: response must stay well under.
"""

import time
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_crtsh_timeout_is_3s():
    """Sanity: CRTSH_TIMEOUT lowered from 10 to 3."""
    from config import CRTSH_TIMEOUT

    assert CRTSH_TIMEOUT == 3, f"Expected 3, got {CRTSH_TIMEOUT}"


def test_dkim_date_window_is_14_days():
    """Sanity: DKIM date-based selector window = 14 days (reduced from 30)."""
    from domain.recon import DKIM_DATE_WINDOW_DAYS

    assert DKIM_DATE_WINDOW_DAYS == 14, f"Expected 14, got {DKIM_DATE_WINDOW_DAYS}"


def test_domain_report_cached_under_500ms(client):
    """Cached response path must be fast (<0.5s, no network calls)."""
    from db import save_cached_domain

    # Test client is unauthenticated → free tier → tier-prefixed cache key
    save_cached_domain("free:example.com", {"domain": "example.com"})
    t0 = time.perf_counter()
    r = client.get("/v1/domain/example.com")
    elapsed = time.perf_counter() - t0
    assert r.status_code == 200
    assert elapsed < 0.5, f"Cached hit took {elapsed:.2f}s"


def test_domain_report_lite_under_1s(client):
    """Lite mode — patched upstream, must finish quickly (<1s)."""
    fake = {"domain": "example.com"}
    with patch("domain.routes.full_domain_report", return_value=fake):
        t0 = time.perf_counter()
        r = client.get("/v1/domain/example.com?lite=true")
        elapsed = time.perf_counter() - t0
    assert r.status_code == 200
    assert elapsed < 1.0, f"Lite took {elapsed:.2f}s"
