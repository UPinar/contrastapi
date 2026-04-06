"""Tests for Wayback Machine / Web Archive lookup."""

from unittest.mock import MagicMock, patch

import httpx
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


# =========== archive.py unit tests ===========


class TestWaybackLookup:
    @patch("domain.archive._client")
    def test_valid_domain_returns_snapshots(self, mock_client):
        mock_resp = MagicMock()
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

    @patch("domain.archive._client")
    def test_empty_results(self, mock_client):
        mock_resp = MagicMock()
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

    @patch("domain.archive._client")
    def test_headers_only_response(self, mock_client):
        """CDX returns only the header row — no actual data."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = [["timestamp", "statuscode", "mimetype", "digest"]]
        mock_resp.raise_for_status = MagicMock()
        mock_client.get.return_value = mock_resp

        from domain.archive import wayback_lookup

        result = wayback_lookup("example.com")
        assert result["total_snapshots"] == 0

    @patch("domain.archive._client")
    def test_timeout_returns_error_dict(self, mock_client):
        mock_client.get.side_effect = httpx.ReadTimeout("timed out")

        from domain.archive import wayback_lookup

        result = wayback_lookup("slow-domain.com")
        assert result["total_snapshots"] == 0
        assert result["first_seen"] is None
        assert "no archived snapshots" in result["summary"]
        assert "web.archive.org" in result["archive_url"]

    @patch("domain.archive._client")
    def test_http_error_returns_error_dict(self, mock_client):
        mock_client.get.side_effect = httpx.HTTPStatusError("503", request=MagicMock(), response=MagicMock())

        from domain.archive import wayback_lookup

        result = wayback_lookup("example.com")
        assert result["total_snapshots"] == 0

    @patch("domain.archive._client")
    def test_malformed_rows_skipped(self, mock_client):
        """CDX rows with wrong number of fields are silently skipped."""
        mock_resp = MagicMock()
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


# =========== route tests ===========


class TestWaybackRoute:
    @patch("domain.archive._client")
    def test_valid_domain(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.json.return_value = CDX_RESPONSE
        mock_resp.raise_for_status = MagicMock()
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
        mock_resp.json.return_value = []
        mock_resp.raise_for_status = MagicMock()
        mock_client.get.return_value = mock_resp

        resp = client.get("/v1/archive/no-archive.com")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_snapshots"] == 0
        assert data["snapshots"] == []
