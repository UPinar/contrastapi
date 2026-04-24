"""Tests for username OSINT lookup endpoint."""

from unittest.mock import MagicMock, patch

import httpx
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


# =========== username_lookup unit tests ===========


class TestUsernameLookupUnit:
    def test_empty_username(self):
        from domain.username import username_lookup

        result = username_lookup("")
        assert "error" in result
        assert result["error"] == "Username is required"

    def test_whitespace_only(self):
        from domain.username import username_lookup

        result = username_lookup("   ")
        assert "error" in result

    def test_too_long(self):
        from domain.username import username_lookup

        result = username_lookup("a" * 100)
        assert "error" in result
        assert "too long" in result["error"]
        assert "username" not in result  # no input echo on error

    def test_path_traversal_blocked(self):
        from domain.username import username_lookup

        result = username_lookup("../etc/passwd")
        assert "error" in result

    def test_null_byte_blocked(self):
        from domain.username import username_lookup

        result = username_lookup("user\x00")
        assert "error" in result

    def test_invalid_chars(self):
        from domain.username import username_lookup

        result = username_lookup("user name!")
        assert "error" in result
        assert "Invalid characters" in result["error"]

    def test_invalid_chars_slash(self):
        from domain.username import username_lookup

        result = username_lookup("user/name")
        assert "error" in result

    def test_at_prefix_stripped(self):
        from domain.username import username_lookup

        with patch("domain.username._pool") as mock_pool:
            resp_404 = MagicMock()
            resp_404.status_code = 404
            mock_future = MagicMock()
            mock_future.result.return_value = {"platform": "github", "url": "", "status": "not_found"}
            mock_pool.submit.return_value = mock_future
            result = username_lookup("@testuser")
            assert result["username"] == "testuser"

    def test_case_preserved(self):
        from domain.username import username_lookup

        with patch("domain.username._pool") as mock_pool:
            mock_future = MagicMock()
            mock_future.result.return_value = {"platform": "github", "url": "", "status": "not_found"}
            mock_pool.submit.return_value = mock_future
            result = username_lookup("MyUser")
            assert result["username"] == "MyUser"

    @patch("domain.username._client")
    def test_found_platforms(self, mock_client):
        from domain.username import _check_platform

        resp_200 = MagicMock()
        resp_200.status_code = 200
        mock_client.head.return_value = resp_200

        result = _check_platform("github", "https://github.com/test", "https://github.com/test", "head", None)
        assert result["status"] == "found"

    @patch("domain.username._client")
    def test_404_is_not_found(self, mock_client):
        from domain.username import _check_platform

        resp_404 = MagicMock()
        resp_404.status_code = 404
        mock_client.head.return_value = resp_404

        result = _check_platform("github", "https://github.com/test", "https://github.com/test", "head", None)
        assert result["status"] == "not_found"

    @patch("domain.username.time.sleep")
    @patch("domain.username._client")
    def test_403_persistent_marked_blocked(self, mock_client, mock_sleep):
        from domain.username import _check_platform

        resp_403 = MagicMock()
        resp_403.status_code = 403
        mock_client.head.return_value = resp_403

        result = _check_platform("twitter", "https://x.com/test", "https://x.com/test", "head", None)
        assert result["status"] == "blocked"

    @patch("domain.username.time.sleep")
    @patch("domain.username._client")
    def test_429_persistent_marked_rate_limited(self, mock_client, mock_sleep):
        from domain.username import _check_platform

        resp_429 = MagicMock()
        resp_429.status_code = 429
        mock_client.head.return_value = resp_429

        result = _check_platform("github", "https://github.com/test", "https://github.com/test", "head", None)
        assert result["status"] == "rate_limited"

    @patch("domain.username._client")
    def test_redirect_is_found(self, mock_client):
        from domain.username import _check_platform

        resp_302 = MagicMock()
        resp_302.status_code = 302
        mock_client.head.return_value = resp_302

        result = _check_platform("github", "https://github.com/test", "https://github.com/test", "head", None)
        assert result["status"] == "found"

    @patch("domain.username.time.sleep")
    @patch("domain.username._client")
    def test_timeout_handled(self, mock_client, mock_sleep):
        from domain.username import _check_platform

        mock_client.head.side_effect = httpx.TimeoutException("timeout")

        result = _check_platform("github", "https://github.com/test", "https://github.com/test", "head", None)
        assert result["status"] == "timeout"

    @patch("domain.username._client")
    def test_body_indicator_not_found(self, mock_client):
        from domain.username import _check_platform

        resp = MagicMock()
        resp.status_code = 200
        resp.text = "<html>The specified profile could not be found</html>"
        mock_client.get.return_value = resp

        result = _check_platform(
            "steam", "https://steamcommunity.com/id/x", "https://steamcommunity.com/id/x", "get", "could not be found"
        )
        assert result["status"] == "not_found"

    @patch("domain.username._client")
    def test_body_indicator_found(self, mock_client):
        from domain.username import _check_platform

        resp = MagicMock()
        resp.status_code = 200
        resp.text = "<html>Welcome to my Steam profile</html>"
        mock_client.get.return_value = resp

        result = _check_platform(
            "steam", "https://steamcommunity.com/id/x", "https://steamcommunity.com/id/x", "get", "could not be found"
        )
        assert result["status"] == "found"

    @patch("domain.username._client")
    def test_inverted_indicator_found(self, mock_client):
        from domain.username import _check_platform

        resp = MagicMock()
        resp.status_code = 200
        resp.text = '<div class="tgme_page_extra">123 subscribers</div>'
        mock_client.get.return_value = resp

        result = _check_platform("telegram", "https://t.me/x", "https://t.me/x", "get", "!tgme_page_extra")
        assert result["status"] == "found"

    @patch("domain.username._client")
    def test_inverted_indicator_not_found(self, mock_client):
        from domain.username import _check_platform

        resp = MagicMock()
        resp.status_code = 200
        resp.text = "<html>generic page without the indicator</html>"
        mock_client.get.return_value = resp

        result = _check_platform("telegram", "https://t.me/x", "https://t.me/x", "get", "!tgme_page_extra")
        assert result["status"] == "not_found"

    @patch("domain.username._client")
    def test_summary_format_found(self, mock_client):
        from domain.username import username_lookup

        resp_200 = MagicMock()
        resp_200.status_code = 200
        resp_200.text = ""
        mock_client.head.return_value = resp_200
        mock_client.get.return_value = resp_200

        result = username_lookup("torvalds")
        assert "torvalds" in result["summary"]
        assert "found on" in result["summary"]

    @patch("domain.username._client")
    def test_summary_format_not_found(self, mock_client):
        from domain.username import username_lookup

        resp_404 = MagicMock()
        resp_404.status_code = 404
        mock_client.head.return_value = resp_404
        mock_client.get.return_value = resp_404

        result = username_lookup("xyznonexistent999")
        assert "not found" in result["summary"]

    @patch("domain.username._client")
    def test_found_count_matches(self, mock_client):
        from domain.username import username_lookup

        resp_200 = MagicMock()
        resp_200.status_code = 200
        resp_200.text = ""
        mock_client.head.return_value = resp_200
        mock_client.get.return_value = resp_200

        result = username_lookup("allplatforms")
        found = [r for r in result["results"] if r["status"] == "found"]
        assert result["found_count"] == len(found)

    @patch("domain.username._client")
    def test_all_platforms_in_results(self, mock_client):
        from domain.username import PLATFORMS, username_lookup

        resp_404 = MagicMock()
        resp_404.status_code = 404
        mock_client.head.return_value = resp_404
        mock_client.get.return_value = resp_404

        result = username_lookup("testuser")
        result_platforms = {r["platform"] for r in result["results"]}
        expected_platforms = {p[0] for p in PLATFORMS}
        assert result_platforms == expected_platforms


# =========== route tests ===========


class TestUsernameRoute:
    @patch("domain.routes.authenticate")
    @patch("domain.routes.username_lookup")
    def test_valid_username(self, mock_lookup, mock_auth):
        mock_lookup.return_value = {
            "username": "testuser",
            "found_count": 1,
            "checked_count": 16,
            "results": [{"platform": "github", "url": "https://github.com/testuser", "status": "found"}],
            "summary": "testuser — found on 1/16 platforms (github)",
        }
        r = client.get("/v1/username/testuser")
        assert r.status_code == 200
        data = r.json()
        assert data["username"] == "testuser"
        assert data["found_count"] == 1

    @patch("domain.routes.authenticate")
    @patch("domain.routes.username_lookup")
    def test_invalid_username(self, mock_lookup, mock_auth):
        mock_lookup.return_value = {
            "username": "bad!user",
            "error": "Invalid characters (allowed: a-z, 0-9, dot, underscore, hyphen)",
        }
        r = client.get("/v1/username/bad!user")
        assert r.status_code == 200
        data = r.json()
        assert "error" in data

    @patch("domain.routes.authenticate")
    @patch("domain.routes.username_lookup")
    def test_response_shape(self, mock_lookup, mock_auth):
        mock_lookup.return_value = {
            "username": "shapetest",
            "found_count": 0,
            "checked_count": 16,
            "results": [],
            "summary": "shapetest — not found on any of 16 platforms checked",
        }
        r = client.get("/v1/username/shapetest")
        assert r.status_code == 200
        data = r.json()
        expected_keys = {"username", "found_count", "checked_count", "results", "summary"}
        assert expected_keys.issubset(set(data.keys()))


# =========== retry / UA rotation / verdict tests ===========


class TestUsernameRetryAndVerdict:
    @patch("domain.username.time.sleep")
    @patch("domain.username._client")
    def test_429_then_success(self, mock_client, mock_sleep):
        from domain.username import _check_platform

        resp_429 = MagicMock()
        resp_429.status_code = 429
        resp_200 = MagicMock()
        resp_200.status_code = 200
        mock_client.head.side_effect = [resp_429, resp_200]

        result = _check_platform("github", "https://github.com/test", "https://github.com/test", "head", None)
        assert result["status"] == "found"
        assert mock_client.head.call_count == 2

    @patch("domain.username.time.sleep")
    @patch("domain.username._client")
    def test_ua_rotates_between_retries(self, mock_client, mock_sleep):
        from domain.username import _USER_AGENTS, _check_platform

        resp_429 = MagicMock()
        resp_429.status_code = 429
        mock_client.head.return_value = resp_429

        _check_platform("github", "https://github.com/test", "https://github.com/test", "head", None)

        seen_uas = [call.kwargs["headers"]["User-Agent"] for call in mock_client.head.call_args_list]
        assert len(seen_uas) >= 2
        assert seen_uas[0] != seen_uas[1]
        assert all(ua in _USER_AGENTS for ua in seen_uas)

    @patch("domain.username.time.sleep")
    @patch("domain.username._client")
    def test_npm_gets_referer_header(self, mock_client, mock_sleep):
        from domain.username import _check_platform

        resp_200 = MagicMock()
        resp_200.status_code = 200
        mock_client.head.return_value = resp_200

        _check_platform("npm", "https://www.npmjs.com/~test", "https://www.npmjs.com/~test", "head", None)

        sent_headers = mock_client.head.call_args.kwargs["headers"]
        assert sent_headers.get("Referer") == "https://www.npmjs.com/"

    @patch("domain.username.time.sleep")
    @patch("domain.username._client")
    def test_other_platform_no_referer(self, mock_client, mock_sleep):
        from domain.username import _check_platform

        resp_200 = MagicMock()
        resp_200.status_code = 200
        mock_client.head.return_value = resp_200

        _check_platform("github", "https://github.com/test", "https://github.com/test", "head", None)

        sent_headers = mock_client.head.call_args.kwargs["headers"]
        assert "Referer" not in sent_headers

    @patch("domain.username.time.sleep")
    @patch("domain.username._client")
    def test_retry_count_respects_max(self, mock_client, mock_sleep):
        from config import USERNAME_MAX_RETRIES
        from domain.username import _check_platform

        resp_429 = MagicMock()
        resp_429.status_code = 429
        mock_client.head.return_value = resp_429

        _check_platform("github", "https://github.com/test", "https://github.com/test", "head", None)
        assert mock_client.head.call_count == USERNAME_MAX_RETRIES + 1

    @patch("domain.username.time.sleep")
    @patch("domain.username._client")
    def test_verdict_partial_when_failures(self, mock_client, mock_sleep):
        from domain.username import PLATFORMS, username_lookup

        resp_429 = MagicMock()
        resp_429.status_code = 429
        resp_429.text = ""
        mock_client.head.return_value = resp_429
        mock_client.get.return_value = resp_429

        result = username_lookup("torvalds")
        assert "verdict" in result
        assert result["verdict"]["completeness"] == "partial"
        assert len(result["verdict"]["sources_unavailable"]) > 0
        assert set(result["verdict"]["sources_queried"]) == {p[0] for p in PLATFORMS}

    @patch("domain.username.time.sleep")
    @patch("domain.username._client")
    def test_verdict_complete_when_all_resolve(self, mock_client, mock_sleep):
        from domain.username import username_lookup

        resp_404 = MagicMock()
        resp_404.status_code = 404
        resp_404.text = ""
        mock_client.head.return_value = resp_404
        mock_client.get.return_value = resp_404

        result = username_lookup("neverexistsuser999xyz")
        assert result["verdict"]["completeness"] == "complete"
        assert result["verdict"]["sources_unavailable"] == []
