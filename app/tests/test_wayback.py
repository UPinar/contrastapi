"""Tests for Wayback Machine / Web Archive lookup."""

from unittest.mock import MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

# Sample CDX API response: first row is headers, rest are data
CDX_RESPONSE = [
    ["timestamp", "statuscode", "mimetype", "digest"],
    ["20260401123045", "200", "text/html", "ABC123"],
    ["20250315100000", "200", "text/html", "DEF456"],
    ["20200101080000", "301", "text/html", "GHI789"],
]


@pytest.fixture(autouse=True)
def _clear_wayback_cache():
    from domain.archive import _wayback_cache

    _wayback_cache.clear()
    yield


# =========== archive.py unit tests ===========


class TestWaybackLookup:
    @patch("domain.archive._client")
    def test_valid_domain_returns_snapshots(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = CDX_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_client.get.return_value = mock_resp

        from domain.archive import wayback_lookup

        result = wayback_lookup("example.com")
        assert result["domain"] == "example.com"
        assert result["total_snapshots"] == 3
        assert result["first_seen"] == "2020-01-01"
        assert result["last_seen"] == "2026-04-01"
        assert result["years_online"] == 6
        assert len(result["snapshots"]) == 3
        # Newest first
        assert result["snapshots"][0]["timestamp"] == "20260401"
        assert result["snapshots"][0]["date"] == "2026-04-01"
        assert result["snapshots"][0]["status"] == "200"
        assert "web.archive.org" in result["snapshots"][0]["url"]
        assert "example.com" in result["summary"]
        assert "3 snapshots" in result["summary"]
        assert result.get("warnings") == []

    @patch("domain.archive._client")
    def test_empty_results(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = []
        mock_resp.raise_for_status = MagicMock()
        mock_client.get.return_value = mock_resp

        from domain.archive import wayback_lookup

        result = wayback_lookup("nonexistent-domain-xyz.com")
        assert result["total_snapshots"] == 0
        assert result["first_seen"] is None
        assert result["last_seen"] is None
        assert result["snapshots"] == []
        assert "no archived snapshots" in result["summary"]
        assert result.get("warnings") == []

    @patch("domain.archive._client")
    def test_headers_only_response(self, mock_client):
        """CDX returns only the header row — no actual data."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [["timestamp", "statuscode", "mimetype", "digest"]]
        mock_resp.raise_for_status = MagicMock()
        mock_client.get.return_value = mock_resp

        from domain.archive import wayback_lookup

        result = wayback_lookup("example.com")
        assert result["total_snapshots"] == 0
        assert result.get("warnings") == []

    @patch("domain.archive._client")
    def test_timeout_returns_error_dict(self, mock_client):
        mock_client.get.side_effect = httpx.ReadTimeout("timed out")

        from domain.archive import wayback_lookup

        result = wayback_lookup("slow-domain.com")
        # Bug I: timeout MUST NOT be reported as "no archived snapshots".
        # total_snapshots is None (unknown), status='unavailable', honest summary.
        assert result["status"] == "unavailable"
        assert result["total_snapshots"] is None
        assert result["first_seen"] is None
        assert "no archived snapshots" not in result["summary"]
        assert "unavailable" in result["summary"]
        assert "cdx_timeout" in result["summary"]
        assert "unknown" in result["summary"]
        assert "web.archive.org" in result["archive_url"]
        assert result.get("warnings") == ["cdx_timeout"]

    @patch("domain.archive._client")
    def test_http_status_error_5xx(self, mock_client):
        """HTTPStatusError with 5xx → cdx_unavailable."""
        mock_client.get.side_effect = httpx.HTTPStatusError(
            "503", request=MagicMock(), response=MagicMock(status_code=503)
        )

        from domain.archive import wayback_lookup

        result = wayback_lookup("example.com")
        assert result["status"] == "unavailable"
        assert result["total_snapshots"] is None
        assert result.get("warnings") == ["cdx_unavailable"]

    @patch("domain.archive._client")
    def test_http_status_error_4xx(self, mock_client):
        """HTTPStatusError with 4xx → cdx_error (distinguished from 5xx)."""
        mock_client.get.side_effect = httpx.HTTPStatusError(
            "404", request=MagicMock(), response=MagicMock(status_code=404)
        )

        from domain.archive import wayback_lookup

        result = wayback_lookup("example.com")
        assert result["status"] == "unavailable"
        assert result["total_snapshots"] is None
        assert result.get("warnings") == ["cdx_error"]

    @patch("domain.archive._client")
    def test_malformed_rows_skipped(self, mock_client):
        """CDX rows with wrong number of fields are silently skipped."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            ["timestamp", "statuscode", "mimetype", "digest"],
            ["20260401123045", "200", "text/html", "ABC"],
            ["20250315100000", "200"],  # too few fields
            ["20240101080000", "200", "text/html", "DEF", "extra"],  # too many fields
        ]
        mock_resp.raise_for_status = MagicMock()
        mock_client.get.return_value = mock_resp

        from domain.archive import wayback_lookup

        result = wayback_lookup("example.com")
        assert result["total_snapshots"] == 1
        assert result["snapshots"][0]["timestamp"] == "20260401"
        assert result.get("warnings") == []

    def test_parse_date_short_timestamp(self):
        """Short timestamps (< 8 chars) are returned as-is."""
        from domain.archive import _parse_date

        assert _parse_date("20260401123045") == "2026-04-01"
        assert _parse_date("20260401") == "2026-04-01"
        assert _parse_date("2026") == "2026"
        assert _parse_date("") == ""

    @patch("domain.archive._client")
    def test_single_snapshot(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            ["timestamp", "statuscode", "mimetype", "digest"],
            ["20260401000000", "200", "text/html", "XYZ"],
        ]
        mock_resp.raise_for_status = MagicMock()
        mock_client.get.return_value = mock_resp

        from domain.archive import wayback_lookup

        result = wayback_lookup("example.com")
        assert result["total_snapshots"] == 1
        assert result["years_online"] == 1
        assert "1 snapshot" in result["summary"]
        assert result.get("warnings") == []

    # =========== new tests ===========

    @patch("domain.archive._client")
    def test_rate_limit_429(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 429

        mock_client.get.return_value = mock_resp

        from domain.archive import wayback_lookup

        result = wayback_lookup("ratelimited.com")
        assert result["status"] == "unavailable"
        assert result["total_snapshots"] is None
        assert result.get("warnings") == ["cdx_rate_limited"]

    @patch("domain.archive._client")
    def test_5xx_unavailable(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 503

        mock_client.get.return_value = mock_resp

        from domain.archive import wayback_lookup

        result = wayback_lookup("unavailable.com")
        assert result["status"] == "unavailable"
        assert result["total_snapshots"] is None
        assert result.get("warnings") == ["cdx_unavailable"]

    @patch("domain.archive._client")
    def test_body_size_cap(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.content = b"x" * (50 * 1024 * 1024 + 1)

        mock_client.get.return_value = mock_resp

        from domain.archive import wayback_lookup

        result = wayback_lookup("bigarchive.com")
        assert result["status"] == "unavailable"
        assert result["total_snapshots"] is None
        assert result.get("warnings") == ["cdx_body_too_large"]

    @patch("domain.archive._client")
    def test_large_domain_no_truncation(self, mock_client):
        header = ["timestamp", "statuscode", "mimetype", "digest"]
        data_rows = [[f"2026010{i % 10}120000", "200", "text/html", f"DIGEST{i}"] for i in range(5000)]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.content = b"x"  # under limit
        mock_resp.json.return_value = [header, *data_rows]

        mock_client.get.return_value = mock_resp

        from domain.archive import wayback_lookup

        result = wayback_lookup("largearchive.com")
        assert result["total_snapshots"] == 5000
        # Bug H regression: CDX limit param must be raised from 20 → 10000
        call_params = mock_client.get.call_args.kwargs["params"]
        assert call_params["limit"] == 10000

    @patch("domain.archive._client")
    def test_cache_hit_ttl(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.content = b"x"
        mock_resp.json.return_value = CDX_RESPONSE

        mock_client.get.return_value = mock_resp

        from domain.archive import wayback_lookup

        result1 = wayback_lookup("cache-test.com")
        result2 = wayback_lookup("cache-test.com")

        assert mock_client.get.call_count == 1
        assert result1 == result2

    @patch("domain.archive._client")
    def test_json_parse_error(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.content = b"x"
        mock_resp.json.side_effect = ValueError("bad json")

        mock_client.get.return_value = mock_resp

        from domain.archive import wayback_lookup

        result = wayback_lookup("parseerror.com")
        assert result["status"] == "unavailable"
        assert result["total_snapshots"] is None
        assert result.get("warnings") == ["cdx_parse_error"]


class TestWaybackUnavailableHonesty:
    """Bug I — Wayback CDX failure must not be reported as 'no snapshots'.

    Heavy domains (kernel.org, archive.org, microsoft.com) routinely time out
    the CDX endpoint despite holding millions of snapshots. The previous
    contract emitted total_snapshots=0 + summary 'no archived snapshots
    found' on every error path, silently lying about archive presence.

    Pin: status='unavailable' + total_snapshots is None + summary tells the
    agent the count is unknown and points at archive_url for manual check.
    """

    @patch("domain.archive._client")
    def test_unavailable_summary_is_honest(self, mock_client):
        mock_client.get.side_effect = httpx.ReadTimeout("timed out")

        from domain.archive import wayback_lookup

        result = wayback_lookup("kernel-like.com")
        # Honest framing: no false "0 snapshots" claim
        assert "no archived snapshots" not in result["summary"]
        assert "Wayback CDX unavailable" in result["summary"]
        assert "unknown" in result["summary"]
        # Manual fallback URL surfaced for the agent
        assert result["archive_url"] in result["summary"]

    @patch("domain.archive._client")
    def test_unavailable_omits_count_fields(self, mock_client):
        mock_client.get.side_effect = httpx.ReadTimeout("timed out")

        from domain.archive import wayback_lookup

        result = wayback_lookup("slow.com")
        assert result["total_snapshots"] is None
        assert result["years_online"] is None
        assert result["snapshots"] == []

    @patch("domain.archive._client")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_route_drops_null_total_via_exclude_none(self, _mock_validate, mock_client):
        """response_model_exclude_none=True must drop total_snapshots from the wire."""
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.content = b"x"
        mock_client.get.return_value = mock_resp

        resp = client.get("/v1/archive/ratelimited-route.com")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "unavailable"
        # total_snapshots and years_online must NOT appear on the wire — agents
        # that key on .total_snapshots will get a KeyError and know to check status.
        assert "total_snapshots" not in body
        assert "years_online" not in body
        assert body["warnings"] == ["cdx_rate_limited"]

    @patch("domain.archive._client")
    def test_unavailable_uses_short_ttl(self, mock_client):
        """Bug I: a transient CDX hiccup must not poison the cache for 24h.

        Pin: status='unavailable' entries respect WAYBACK_CACHE_TTL_UNAVAILABLE
        (5 min) instead of the long 24h TTL used for confirmed responses.
        """
        from domain.archive import _wayback_cache, wayback_lookup

        # First call: simulate timeout → cache stores 'unavailable'
        mock_client.get.side_effect = httpx.ReadTimeout("timed out")
        first = wayback_lookup("flapping.example.com")
        assert first["status"] == "unavailable"
        assert mock_client.get.call_count == 1

        # Manually age the cache entry past the short TTL (300s) but well under
        # the long TTL (86400s). The next call MUST re-fetch, not serve stale.
        with patch("domain.archive.time.time") as mock_time:
            cached_at = _wayback_cache["flapping.example.com"][1]
            mock_time.return_value = cached_at + 400  # 6m40s — past 5m short TTL

            mock_client.get.side_effect = None
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = CDX_RESPONSE
            mock_resp.raise_for_status = MagicMock()
            mock_resp.content = b"x"
            mock_client.get.return_value = mock_resp

            second = wayback_lookup("flapping.example.com")

        assert second["status"] == "ok"
        assert second["total_snapshots"] == 3
        assert mock_client.get.call_count == 2  # re-fetched, not served from stale cache

    @patch("domain.archive._client")
    def test_ok_response_keeps_long_ttl(self, mock_client):
        """Pin: 'ok' responses still get the 24h TTL — short TTL is unavailable-only."""
        from domain.archive import _wayback_cache, wayback_lookup

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = CDX_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_resp.content = b"x"
        mock_client.get.return_value = mock_resp

        first = wayback_lookup("stable.example.com")
        assert first["status"] == "ok"
        assert mock_client.get.call_count == 1

        # 1 hour later — well past short TTL but well within long TTL
        with patch("domain.archive.time.time") as mock_time:
            cached_at = _wayback_cache["stable.example.com"][1]
            mock_time.return_value = cached_at + 3600

            second = wayback_lookup("stable.example.com")

        assert second == first
        assert mock_client.get.call_count == 1  # served from cache

    @patch("domain.archive._client")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_ok_zero_snapshots_still_emits_count(self, _mock_validate, mock_client):
        """Confirmed-empty (rows fetched, length<2) keeps total_snapshots=0 on the wire."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = []
        mock_resp.raise_for_status = MagicMock()
        mock_resp.content = b"x"
        mock_client.get.return_value = mock_resp

        resp = client.get("/v1/archive/empty-confirmed.com")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert body["total_snapshots"] == 0
        assert "no archived snapshots" in body["summary"]


# =========== route tests ===========


class TestWaybackRoute:
    @patch("domain.archive._client")
    def test_valid_domain(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = CDX_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_resp.content = b"x"
        mock_client.get.return_value = mock_resp

        resp = client.get("/v1/archive/example.com")
        assert resp.status_code == 200
        data = resp.json()
        assert data["domain"] == "example.com"
        assert data["total_snapshots"] == 3
        assert len(data["snapshots"]) == 3
        # Validate schema fields
        snap = data["snapshots"][0]
        assert "timestamp" in snap
        assert "date" in snap
        assert "status" in snap
        assert "mimetype" in snap
        assert "url" in snap
        assert data.get("warnings") == []

    def test_invalid_domain_returns_400(self):
        resp = client.get("/v1/archive/not a domain!")
        assert resp.status_code == 400

    def test_private_ip_domain_rejected(self):
        resp = client.get("/v1/archive/127.0.0.1")
        assert resp.status_code in (400, 403)

    @patch("domain.archive._client")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_empty_results_via_route(self, mock_validate, mock_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = []
        mock_resp.raise_for_status = MagicMock()
        mock_resp.content = b"x"
        mock_client.get.return_value = mock_resp

        resp = client.get("/v1/archive/no-archive.com")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_snapshots"] == 0
        assert data["snapshots"] == []
        assert data.get("warnings") == []
