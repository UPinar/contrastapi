"""Tests for domain/ip_intel.py — cloud provider lookup, Tor exit detection, risk scoring."""

import time
from unittest.mock import MagicMock, patch

import pytricia

# ── helpers ──────────────────────────────────────────────────────────────────


def _make_aws_json():
    return {
        "prefixes": [{"ip_prefix": "3.0.0.0/8", "region": "us-east-1", "service": "EC2"}],
        "ipv6_prefixes": [],
    }


def _make_gcp_json():
    return {
        "prefixes": [{"ipv4Prefix": "8.8.8.0/24"}, {"ipv6Prefix": "2001:4860::/32"}],
    }


def _make_cf_json():
    return {
        "result": {
            "ipv4_cidrs": ["1.1.1.0/24"],
            "ipv6_cidrs": ["2606:4700::/32"],
        }
    }


# ── cloud cache tests ─────────────────────────────────────────────────────────


class TestRefreshCloudCache:
    def setup_method(self):
        import domain.ip_intel as m

        m._cloud_cache = {"v4": None, "v6": None, "fetched_at": 0.0}

    def _stream_ctx(self, body: bytes, content_length: str | None = None):
        """Build a MagicMock acting as httpx streaming response context manager."""
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        headers = {}
        if content_length is not None:
            headers["content-length"] = content_length
        resp.headers.get = lambda k, default=None: headers.get(k, default)
        # iter_bytes yields body in a single chunk
        resp.iter_bytes = lambda: iter([body])
        ctx = MagicMock()
        ctx.__enter__ = lambda s: resp
        ctx.__exit__ = MagicMock(return_value=False)
        return ctx

    def test_aws_only_others_fail(self):
        import json as _json

        import httpx

        aws_body = _json.dumps(_make_aws_json()).encode()

        def stream_side_effect(method, url, **kwargs):
            if "amazonaws" in url:
                return self._stream_ctx(aws_body)
            raise httpx.TimeoutException("timeout")

        with patch("domain.ip_intel._make_http_client") as mock_factory:
            mock_client = MagicMock()
            mock_client.stream.side_effect = stream_side_effect
            mock_factory.return_value = mock_client

            from domain.ip_intel import _refresh_cloud_cache

            v4, v6 = _refresh_cloud_cache()

        # AWS prefix should be present; no exception bubbled
        assert v4.get("3.5.0.1") == "AWS"

    def test_body_cap_returns_previous(self):
        import domain.ip_intel as m

        # Pre-seed cache with AWS prefix; body-cap on all sources should preserve it
        prev_v4 = pytricia.PyTricia(32)
        prev_v4["10.0.0.0/8"] = "AWS"
        prev_v6 = pytricia.PyTricia(128)
        m._cloud_cache = {"v4": prev_v4, "v6": prev_v6, "fetched_at": 0.0}

        # Content-Length declares oversize → early abort, no iter_bytes consumed
        big_ctx = self._stream_ctx(b"", content_length=str(10 * 1024 * 1024))

        with patch("domain.ip_intel._make_http_client") as mock_factory:
            mock_client = MagicMock()
            mock_client.stream.return_value = big_ctx
            mock_factory.return_value = mock_client

            from domain.ip_intel import _refresh_cloud_cache

            v4, _ = _refresh_cloud_cache()

        # All sources hit body cap → previous AWS prefix preserved
        assert v4.get("10.0.0.0/8") == "AWS"

    def test_ttl_hit_skips_fetch(self):
        import domain.ip_intel as m

        v4 = pytricia.PyTricia(32)
        v4["3.0.0.0/8"] = "AWS"
        v6 = pytricia.PyTricia(128)
        m._cloud_cache = {"v4": v4, "v6": v6, "fetched_at": time.time()}

        with patch("domain.ip_intel._make_http_client") as mock_factory:
            from domain.ip_intel import _refresh_cloud_cache

            _refresh_cloud_cache()
            mock_factory.assert_not_called()


# ── tor cache tests ───────────────────────────────────────────────────────────


class TestRefreshTorCache:
    def setup_method(self):
        import domain.ip_intel as m

        m._tor_cache = {"data": frozenset(), "fetched_at": 0.0}

    def test_parses_plaintext(self):
        tor_text = "1.2.3.4\n5.6.7.8\n# comment\n\n9.9.9.9\n"
        body = tor_text.encode()

        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.headers.get = lambda k, default=None: None
        resp.iter_bytes = lambda: iter([body])
        ctx = MagicMock()
        ctx.__enter__ = lambda s: resp
        ctx.__exit__ = MagicMock(return_value=False)

        with patch("domain.ip_intel._make_http_client") as mock_factory:
            mock_client = MagicMock()
            mock_client.stream.return_value = ctx
            mock_factory.return_value = mock_client

            from domain.ip_intel import _refresh_tor_cache

            result = _refresh_tor_cache()

        assert "1.2.3.4" in result
        assert "5.6.7.8" in result
        assert "9.9.9.9" in result
        assert "# comment" not in result

    def test_ttl_hit_skips_fetch(self):
        import domain.ip_intel as m

        m._tor_cache = {"data": frozenset({"1.2.3.4"}), "fetched_at": time.time()}

        with patch("domain.ip_intel._make_http_client") as mock_factory:
            from domain.ip_intel import _refresh_tor_cache

            result = _refresh_tor_cache()
            mock_factory.assert_not_called()

        assert "1.2.3.4" in result


# ── lookup tests ──────────────────────────────────────────────────────────────


class TestCheckCloudProvider:
    def setup_method(self):
        import domain.ip_intel as m

        m._cloud_cache = {"v4": None, "v6": None, "fetched_at": 0.0}

    def test_returns_provider(self):
        import domain.ip_intel as m

        v4 = pytricia.PyTricia(32)
        v4["3.0.0.0/8"] = "AWS"
        v6 = pytricia.PyTricia(128)
        m._cloud_cache = {"v4": v4, "v6": v6, "fetched_at": time.time()}

        from domain.ip_intel import check_cloud_provider

        assert check_cloud_provider("3.5.140.2") == "AWS"

    def test_returns_none_outside_range(self):
        import domain.ip_intel as m

        v4 = pytricia.PyTricia(32)
        v4["3.0.0.0/8"] = "AWS"
        v6 = pytricia.PyTricia(128)
        m._cloud_cache = {"v4": v4, "v6": v6, "fetched_at": time.time()}

        from domain.ip_intel import check_cloud_provider

        assert check_cloud_provider("9.9.9.9") is None

    def test_ipv6_lookup(self):
        import domain.ip_intel as m

        v4 = pytricia.PyTricia(32)
        v6 = pytricia.PyTricia(128)
        v6["2606:4700::/32"] = "Cloudflare"
        m._cloud_cache = {"v4": v4, "v6": v6, "fetched_at": time.time()}

        from domain.ip_intel import check_cloud_provider

        assert check_cloud_provider("2606:4700::1111") == "Cloudflare"


class TestCheckTorExit:
    def setup_method(self):
        import domain.ip_intel as m

        m._tor_cache = {"data": frozenset(), "fetched_at": 0.0}

    def test_ip_in_exit_set(self):
        import domain.ip_intel as m

        m._tor_cache = {"data": frozenset({"5.9.32.230"}), "fetched_at": time.time()}

        from domain.ip_intel import check_tor_exit

        assert check_tor_exit("5.9.32.230") is True

    def test_ip_not_in_exit_set(self):
        import domain.ip_intel as m

        m._tor_cache = {"data": frozenset({"5.9.32.230"}), "fetched_at": time.time()}

        from domain.ip_intel import check_tor_exit

        assert check_tor_exit("8.8.8.8") is False


# ── score_ip tests ────────────────────────────────────────────────────────────


class TestScoreIp:
    def _score(self, reputation=None, ports=None, ptr=None, cloud=None, tor=False):
        from domain.ip_intel import score_ip

        return score_ip(reputation, ports or [], ptr, cloud, tor)

    def test_no_reputation(self):
        score = self._score(reputation=None)
        assert 0 <= score <= 100

    def test_clamps_high(self):
        rep = {"abuseipdb": {"abuse_score": 100}}
        score = self._score(reputation=rep, ports=list(range(50)), tor=True)
        assert score >= 90

    def test_clamps_low(self):
        score = self._score(reputation={"abuseipdb": {"abuse_score": 0}}, cloud="GCP", ptr="dns.google")
        assert score == 0

    def test_high_risk_tor_abuse(self):
        rep = {"abuseipdb": {"abuse_score": 90}}
        score = self._score(reputation=rep, tor=True)
        assert score >= 70

    def test_low_risk_clean_cloud_ptr(self):
        rep = {"abuseipdb": {"abuse_score": 0}}
        score = self._score(reputation=rep, cloud="GCP", ptr="dns.google")
        assert score <= 15

    def test_tor_penalty_applied(self):
        score_no_tor = self._score()
        score_tor = self._score(tor=True)
        assert score_tor > score_no_tor

    def test_cloud_bonus_applied(self):
        # use tor=True to create baseline risk so cloud bonus is visible
        score_no_cloud = self._score(tor=True)
        score_cloud = self._score(tor=True, cloud="AWS")
        assert score_cloud < score_no_cloud

    def test_none_abuse_score(self):
        rep = {"abuseipdb": {"abuse_score": None}}
        score = self._score(reputation=rep)
        assert 0 <= score <= 100
